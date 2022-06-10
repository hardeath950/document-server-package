# runas administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{ 
  Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
  exit
}

if ( $argsCount -ge 2 )
{ 
  $letsencrypt_root_dir = "M4_DS_ROOT\..\..\..\Certbot\live"
  $root_dir = "M4_DS_ROOT\letsencrypt"
  $nginx_conf_dir = "M4_DS_ROOT\nginx\conf"
  $nginx_conf = "ds.conf"
  $nginx_tmpl = "ds-ssl.conf.tmpl"
  $proxy_service = "DsProxySvc"

  $letsencrypt_domain = $args[1]
  $letsencrypt_mail = $args[0]

  "certbot certonly --expand --webroot -w `"${root_dir}`" --noninteractive --agree-tos --email ${letsencrypt_mail} -d ${letsencrypt_domain}" > "M4_DS_ROOT\Logs\le-start.log"
  cmd.exe /c "certbot certonly --expand --webroot -w `"${root_dir}`" --noninteractive --agree-tos --email ${letsencrypt_mail} -d ${letsencrypt_domain}" > "M4_DS_ROOT\Logs\le-new.log"

  $ssl_cert = "${letsencrypt_root_dir}\${letsencrypt_domain}\fullchain.pem".Replace('\', '/')
  $ssl_key = "${letsencrypt_root_dir}\${letsencrypt_domain}\privkey.pem".Replace('\', '/')

  if ( [System.IO.File]::Exists($ssl_cert) -and [System.IO.File]::Exists($ssl_key) -and [System.IO.File]::Exists("${nginx_conf_dir}\${nginx_tmpl}"))
  {
    $secure_link_secret = (Select-String -Path "${nginx_conf_dir}\${nginx_conf}" -Pattern "secure_link_secret (.*)").Matches.Groups[1].Value
    Copy-Item "${nginx_conf_dir}\${nginx_tmpl}" -Destination "${nginx_conf_dir}\${nginx_conf}"
    ((Get-Content -Path "${nginx_conf_dir}\${nginx_conf}" -Raw) -replace 'secure_link_secret (.*)', "secure_link_secret $secure_link_secret") | Set-Content -Path "${nginx_conf_dir}\${nginx_conf}"
    ((Get-Content -Path "${nginx_conf_dir}\${nginx_conf}" -Raw) -replace '{SSL_CERTIFICATE_PATH}', $ssl_cert) | Set-Content -Path "${nginx_conf_dir}\${nginx_conf}"
    ((Get-Content -Path "${nginx_conf_dir}\${nginx_conf}" -Raw) -replace '{SSL_KEY_PATH}', $ssl_key) | Set-Content -Path "${nginx_conf_dir}\${nginx_conf}"
  }

  Restart-Service -Name $proxy_service

  "certbot renew >> `"M4_DS_ROOT\Logs\le-renew.log`"`nRestart-Service -Name $proxy_service" > "M4_DS_ROOT\letsencrypt\letsencrypt_cron.ps1"

  $day = (Get-Date -Format "dddd").ToUpper().SubString(0, 3)
  $time = Get-Date -Format "HH:mm"
  cmd.exe /c "SCHTASKS /CREATE /SC WEEKLY /D $day /TN `"Certbot renew`" /TR `"M4_DS_ROOT\letsencrypt\letsencrypt_cron.ps1`" /ST $time"
}
else
{
  Write-Output " This script provided to automatically get Let's Encrypt SSL Certificates for AppServer "
  Write-Output " usage: "
  Write-Output "   letsencrypt.ps1 EMAIL DOMAIN "
  Write-Output "      EMAIL       Email used for registration and recovery contact. Use "
  Write-Output "                  comma to register multiple emails, ex: "
  Write-Output "                  u1@example.com,u2@example.com. "
  Write-Output "      DOMAIN      Domain name to apply "
}
