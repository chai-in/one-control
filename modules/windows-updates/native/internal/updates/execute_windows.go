//go:build windows

package updates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"onecontrol/native/internal/featurehost"
	"regexp"
	"runtime"
	"strings"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

type updateID struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
}
type command struct {
	Kind    string     `json:"kind"`
	Updates []updateID `json:"updates,omitempty"`
}

var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Every COM reference belongs to this invocation's locked apartment. Calls stop
// after the first error; no later mutation can run with incomplete search data.
type apartment struct {
	err    error
	values []*ole.VARIANT
	roots  []*ole.IDispatch
}

func (a *apartment) close() {
	for i := len(a.values) - 1; i >= 0; i-- {
		a.values[i].Clear()
	}
	for i := len(a.roots) - 1; i >= 0; i-- {
		a.roots[i].Release()
	}
}
func (a *apartment) object(id string) *ole.IDispatch {
	if a.err != nil {
		return nil
	}
	unknown, err := oleutil.CreateObject(id)
	if err != nil {
		a.err = err
		return nil
	}
	defer unknown.Release()
	dispatch, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		a.err = err
		return nil
	}
	a.roots = append(a.roots, dispatch)
	return dispatch
}
func (a *apartment) invoke(object *ole.IDispatch, mode int16, name string, arguments ...any) *ole.VARIANT {
	if a.err != nil {
		return nil
	}
	if object == nil {
		a.err = errors.New("missing_wua_object")
		return nil
	}
	value, err := object.InvokeWithOptionalArgs(name, mode, arguments)
	if value != nil {
		a.values = append(a.values, value)
	}
	if err != nil {
		a.err = err
		return nil
	}
	return value
}
func (a *apartment) property(object *ole.IDispatch, name string, arguments ...any) *ole.VARIANT {
	return a.invoke(object, ole.DISPATCH_PROPERTYGET, name, arguments...)
}
func (a *apartment) call(object *ole.IDispatch, name string, arguments ...any) *ole.VARIANT {
	return a.invoke(object, ole.DISPATCH_METHOD, name, arguments...)
}
func (a *apartment) set(object *ole.IDispatch, name string, value any) {
	a.invoke(object, ole.DISPATCH_PROPERTYPUT, name, value)
}
func dispatch(value *ole.VARIANT) *ole.IDispatch {
	if value == nil {
		return nil
	}
	return value.ToIDispatch()
}
func text(value *ole.VARIANT) string {
	if value == nil {
		return ""
	}
	return value.ToString()
}
func number(value *ole.VARIANT) int {
	if value == nil {
		return 0
	}
	return int(value.Val)
}
func boolean(value *ole.VARIANT) bool { return value != nil && value.Val != 0 }
func (a *apartment) gate(ctx context.Context) bool {
	if a.err == nil {
		a.err = ctx.Err()
	}
	return a.err == nil
}
func outcome(state string, value any) featurehost.TaskResult {
	raw, _ := json.Marshal(value)
	return featurehost.TaskResult{State: state, Result: raw}
}

func Execute(ctx context.Context, raw json.RawMessage) (result featurehost.TaskResult) {
	var input command
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || (input.Kind != "windows.scan" && input.Kind != "windows.install") || (input.Kind == "windows.scan" && len(input.Updates) != 0) || (input.Kind == "windows.install" && (len(input.Updates) == 0 || len(input.Updates) > 200)) {
		return outcome("failed", map[string]any{"reason": "invalid_update_command"})
	}
	requested := map[updateID]bool{}
	for _, update := range input.Updates {
		update.ID = strings.ToLower(update.ID)
		if !guid.MatchString(update.ID) || update.Revision < 1 || requested[update] {
			return outcome("failed", map[string]any{"reason": "invalid_update_selection"})
		}
		requested[update] = true
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		return outcome("failed", map[string]any{"reason": "windows_update_unavailable"})
	}
	defer ole.CoUninitialize()
	a := &apartment{}
	defer a.close()
	mutated := false
	defer func() {
		if a.err != nil {
			state := "failed"
			if mutated {
				state = "indeterminate"
			}
			result = outcome(state, map[string]any{"reason": "windows_update_incomplete"})
		}
	}()
	if !a.gate(ctx) {
		return
	}
	session := a.object("Microsoft.Update.Session")
	a.set(session, "ClientApplicationID", "One Control")
	searcher := dispatch(a.call(session, "CreateUpdateSearcher"))
	// Leave ServerSelection and ServiceID unchanged to respect WSUS/WUfB.
	found := dispatch(a.call(searcher, "Search", "IsInstalled=0 and IsHidden=0 and Type='Software'"))
	if !a.gate(ctx) {
		return
	}
	if number(a.property(found, "ResultCode")) != 2 {
		return outcome("failed", map[string]any{"reason": "windows_update_search_incomplete"})
	}
	updates := dispatch(a.property(found, "Updates"))
	count := number(a.property(updates, "Count"))
	selected := a.object("Microsoft.Update.UpdateColl")
	available := []map[string]any{}
	matched := []updateID{}
	observed := 0
	for index := 0; index < count && a.gate(ctx); index++ {
		update := dispatch(a.property(updates, "Item", index))
		categories := dispatch(a.property(update, "Categories"))
		featureUpgrade := false
		for c := 0; c < number(a.property(categories, "Count")) && a.err == nil; c++ {
			category := dispatch(a.property(categories, "Item", c))
			if strings.EqualFold(text(a.property(category, "CategoryID")), "3689bdc8-b205-4af4-8d4a-a63924c5e9d5") {
				featureUpgrade = true
			}
		}
		behavior := dispatch(a.property(update, "InstallationBehavior"))
		if featureUpgrade || boolean(a.property(behavior, "CanRequestUserInput")) {
			continue
		}
		identity := dispatch(a.property(update, "Identity"))
		key := updateID{ID: strings.ToLower(text(a.property(identity, "UpdateID"))), Revision: number(a.property(identity, "RevisionNumber"))}
		if !guid.MatchString(key.ID) || key.Revision < 1 {
			a.err = errors.New("invalid_wua_identity")
			break
		}
		observed++
		if len(available) < 256 {
			available = append(available, map[string]any{"id": key.ID, "revision": key.Revision, "title": text(a.property(update, "Title")), "eulaAccepted": boolean(a.property(update, "EulaAccepted"))})
		}
		if requested[key] {
			a.call(selected, "Add", update)
			matched = append(matched, key)
		}
	}
	if !a.gate(ctx) {
		return
	}
	if input.Kind == "windows.scan" {
		return outcome("succeeded", map[string]any{"updates": available, "partial": observed > len(available), "observedCount": observed})
	}
	if len(matched) != len(requested) {
		return outcome("failed", map[string]any{"reason": "approved_updates_no_longer_applicable"})
	}
	for index := range matched {
		if !a.gate(ctx) {
			return
		}
		update := dispatch(a.property(selected, "Item", index))
		if !boolean(a.property(update, "EulaAccepted")) {
			mutated = true
			a.call(update, "AcceptEula")
		}
	}
	if !a.gate(ctx) {
		return
	}
	downloader := dispatch(a.call(session, "CreateUpdateDownloader"))
	a.set(downloader, "Updates", selected)
	downloaded := dispatch(a.call(downloader, "Download"))
	if !a.gate(ctx) {
		return
	}
	if number(a.property(downloaded, "ResultCode")) != 2 {
		return outcome("failed", map[string]any{"reason": "windows_update_download_incomplete"})
	}
	installer := dispatch(a.call(session, "CreateUpdateInstaller"))
	a.set(installer, "Updates", selected)
	a.set(installer, "AllowSourcePrompts", false)
	a.set(installer, "ForceQuiet", true)
	if !a.gate(ctx) {
		return
	}
	// Check the renewed lease immediately before installation. WUA may continue
	// an in-flight install after cancellation; its outcome must remain uncertain.
	mutated = true
	installed := dispatch(a.call(installer, "Install"))
	if !a.gate(ctx) {
		return
	}
	rows := []map[string]any{}
	for index, key := range matched {
		item := dispatch(a.call(installed, "GetUpdateResult", index))
		rows = append(rows, map[string]any{"id": key.ID, "revision": key.Revision, "resultCode": number(a.property(item, "ResultCode")), "hresult": int32(number(a.property(item, "HResult")))})
	}
	state := "indeterminate"
	if number(a.property(installed, "ResultCode")) == 2 {
		state = "succeeded"
	}
	return outcome(state, map[string]any{"updates": rows, "rebootRequired": boolean(a.property(installed, "RebootRequired"))})
}
