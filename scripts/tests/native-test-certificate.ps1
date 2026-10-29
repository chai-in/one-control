#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$IPAddress)
$ErrorActionPreference='Stop'
$key=[Security.Cryptography.RSA]::Create(3072)
try {
  $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=One Control isolated native acceptance',$key,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $names=[Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
  $names.AddIpAddress([Net.IPAddress]::Parse($IPAddress))
  $request.CertificateExtensions.Add($names.Build())
  $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
  $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign,$true))
  $certificate=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddHours(1))
  try {
    [IO.File]::WriteAllText((Join-Path $Directory 'tls-certificate.pem'),$certificate.ExportCertificatePem())
    [IO.File]::WriteAllText((Join-Path $Directory 'tls-private.pem'),$key.ExportPkcs8PrivateKeyPem())
  } finally {$certificate.Dispose()}
} finally {$key.Dispose()}
