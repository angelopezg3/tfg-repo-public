# ================================
# Watcher de capturas TCPDUMP vía ADB
# Copia archivos completos y borra del teléfono
# ================================

# === CONFIGURACIÓN ===
$DevicePath = "/sdcard/captures"                  # Carpeta en el teléfono
$LocalPath  = "C:\SCRIPTS\SAVIA\TFG\pcaps\a"      # Carpeta local donde guardar los PCAPs
$PollSec    = 5                                   # Intervalo de comprobación (segundos)
$DeviceId	= "2a6992b036027ece"

Write-Host "Iniciando watcher. Origen: $DevicePath Destino: $LocalPath"
$copiados = @{}

while ($true) {
	
    # === LISTAR ARCHIVOS EN EL DISPOSITIVO ===
    $raw = & adb -s $DeviceId shell "ls -1 $DevicePath" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Start-Sleep -Seconds $PollSec
		Write-Host "Error listando archivos"
        continue
    }
	# Procesar salida vacía (carpeta sin archivos)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        Start-Sleep -Seconds $PollSec
		Write-Host "Carpeta vacia, 0 archivos"
        continue
    }

    $filesInfo = $raw -split "`r?`n" |
    ForEach-Object {
        $name = $_.Trim()
        if ($name -match '^captura_(\d{5})_(\d{14})\.pcap$') {
            $dateStr = $matches[2]
            $indexStr = $matches[1]

            try {
                $dt = [datetime]::ParseExact($dateStr, 'yyyyMMddHHmmss', $null)
            } catch {
                $dt = [datetime]::MinValue
            }
            [PSCustomObject]@{
                Name  = $name
                Index = [int]$indexStr
                Time  = $dt
            }
        }
    } | Where-Object { $_ -ne $null }

    # ordeno por fecha y luego por index (si hay dos con misma fecha...)
    $filesInfo = $filesInfo | Sort-Object -Property Time, Index
    $files = $filesInfo | Select-Object -ExpandProperty Name

    Write-Host ""
    Write-Host "Archivos totales en el dispositivo: $($files.Count)"
    Write-Host "Listado de archivos:"
    foreach ($file in $files) {
        $remoteFile = "$DevicePath/$file"
        $sizeBytes = & adb -s $DeviceId shell "stat -c%s '$remoteFile'" 2>$null
        $size64 = 0
        if ([int64]::TryParse($sizeBytes, [ref]$size64)) {
            $sizeMB = [math]::Round($size64 / 1MB, 2)
            Write-Host "  $file -> $sizeMB MB"
        } else {
            Write-Host "  $file -> tamaño desconocido"
        }
    }


    if ($files.Count -le 1) {
        # Solo hay 0 o 1 archivo, ninguno completo aún
        Start-Sleep -Seconds $PollSec
        continue
    }

    # === Todos los archivos menos el último (más reciente) ===
    # el ultimo no porque es el que se esta rellenando...
    $completos = $files[0..($files.Count - 2)]
	Write-Host "Archivos completos detectados: $($completos -join ', ')"


    # Filtrar los que aún no hemos copiado
    $aCopiar = $completos | Where-Object { -not $copiados.ContainsKey($_) }
	if ($aCopiar.Count -gt 0) {
        Write-Host "Archivos pendientes de copiar: $($aCopiar -join ', ')"
    } else {
        Write-Host "No hay archivos nuevos para copiar."
    }

    foreach ($file in $aCopiar) {
        $remoteFile = "$DevicePath/$file"
        $localFile  = Join-Path $LocalPath $file

		# === COMPROBAR TAMAÑO ===
		$sizeBytes = & adb -s $DeviceId shell "stat -c%s '$remoteFile'" 2>$null
        $sizeMB = [math]::Round($sizeBytes / 1MB, 2)


        # === COPIAR ===
        Write-Host "Copiando archivo completo: $file ($sizeMB MB) -> $file ..."
        & adb -s $DeviceId pull $remoteFile $localFile | Out-Null

        if (Test-Path $localFile) {
            Write-Host "Copiado: $file"

            # Registrar como copiado
            $copiados[$file] = $true
        } else {
            Write-Warning "Error al copiar: $file"
        }
    }
	# === BORRAR SOLO LOS ARCHIVOS QUE YA TENGAN OTRO MÁS NUEVO ===
    if ($files.Count -ge 2) {
        # Todos menos el último
        $paraBorrar = $files[0..($files.Count - 2)] | Where-Object { $copiados.ContainsKey($_) }

        foreach ($file in $paraBorrar) {
            $remoteFile = "$DevicePath/$file"
            Write-Host "Borrando del telefono: $file"
            & adb -s $DeviceId shell "rm -f '$remoteFile'" | Out-Null
            $copiados.Remove($file) | Out-Null
        }
    }

    Start-Sleep -Seconds $PollSec
}
