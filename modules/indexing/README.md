# Windows Search indexing module

This optional native host is downloaded only when `indexing` is selected. Its server dependency is `command-host`; it requires `indexing.manage`. It is absent from the bootstrap and uses the common leased task protocol.

`indexing.status` reads the Search service/startup setting and the SystemIndex catalog's actual activity, pause reason and item count. It also reads up to 64 configured crawl rules through the supported Search API. Partial enumeration is labeled explicitly. Configured rules do not prove effective access to every location. Windows Server without the Search feature reports `not-installed`.

`indexing.enable` sets an explicitly approved automatic, delayed automatic or manual startup mode and starts Search. `indexing.disable` disables startup and stops it. `indexing.pause` stops the service while preserving its startup mode; `indexing.resume` starts it without re-enabling a disabled service. This pause is explicitly a service-stop fallback: indexed queries are unavailable while stopped. These changes require separate approval and preserve the catalog and crawl rules. The provider never deletes source files or resets the catalog.

Every receipt includes observed before/after state where available. Lease loss after a change starts produces an indeterminate outcome and requires reconciliation. Restored operation intents are not replayed. A service already disabled must be enabled with an approved startup mode before resume.

Timed pause, custom rule editing, file-type/content preferences, persistent baseline restoration and separately approved rebuild remain to be implemented. A true indexing pause is not claimed. The local Windows check reads service/catalog/rules only; control logic uses fake services for mutation tests. The Windows CI service pilot exercises download and read-only command dispatch, not changes to the runner's Search configuration.

API references: [catalog status](https://learn.microsoft.com/en-us/windows/win32/api/searchapi/nf-searchapi-isearchcatalogmanager-getcatalogstatus), [catalog manager](https://learn.microsoft.com/en-us/windows/win32/search/-search-3x-wds-mngidx-catalog-manager), and [Microsoft SearchAPI interface definitions](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/SearchAPI.h).
