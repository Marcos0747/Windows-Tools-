@echo off
@set toolver=1.0
setlocal enabledelayedexpansion



:: ----------------------------------------------------------------------------------------- ::
:: |                            Made by:                                                   | ::
:: |                                     Marcos0747                                        | ::
:: |                 Github:                                                               | ::
:: |                         https://github.com/Marcos0747                                 | ::
:: ----------------------------------------------------------------------------------------- ::



:: -----------------------------------------------------------------------------------------

set items_per_page=10
set total_items=60
set /a total_pages=(total_items + items_per_page - 1) / items_per_page
set current_page=1

:inicio
cls
goto menu

:: -----------------------------------------------------------------------------------------

:menu
cls
call :cabecera

set /a start_item=(current_page - 1) * items_per_page + 1
set /a end_item=start_item + items_per_page - 1
if %end_item% gtr %total_items% set end_item=%total_items%

:: -----------------------------------------------------------------------------------------

echo.
echo        ______________________________________________________________
echo:
echo                        HERRAMIENTAS PARA TU PC - Pagina %current_page%/%total_pages%
echo        ______________________________________________________________
echo:

for /l %%i in (%start_item%,1,%end_item%) do (
    call :mostrar_opcion %%i
)

:: -----------------------------------------------------------------------------------------

echo.
if %current_page% gtr 1 echo        [P] Pagina anterior
if %current_page% lss %total_pages% echo        [N] Pagina siguiente
echo        [X] Salir
echo        ______________________________________________________________
echo.
:: Color thing
echo.
set /p "seleccion=[32mElige una opcion [%start_item%-%end_item%, P, N, X]:[0m "


:: -----------------------------------------------------------------------------------------

if /i "%seleccion%"=="P" if %current_page% gtr 1 set /a current_page-=1 & goto menu
if /i "%seleccion%"=="N" if %current_page% lss %total_pages% set /a current_page+=1 & goto menu
if /i "%seleccion%"=="X" exit


set /a seleccion_valida=0
for /l %%i in (%start_item%,1,%end_item%) do if "%seleccion%"=="%%i" set /a seleccion_valida=1

if "%seleccion_valida%"=="0" goto menu


call :ejecutar_opcion %seleccion%
goto menu

:: -----------------------------------------------------------------------------------------

:mostrar_opcion
if "%1"=="1" echo           [1] Informacion del sistema
if "%1"=="2" echo           [2] Informacion del adaptador de red
if "%1"=="3" echo           [3] Escaneo y reparacion de disco
if "%1"=="4" echo           [4] Comprobar el estado de la red
if "%1"=="5" echo           [5] Administrador de tareas
if "%1"=="6" echo           [6] Informacion de almacenamiento
if "%1"=="7" echo           [7] Monitor de CPU y memoria
if "%1"=="8" echo           [8] Limpiar archivos temporales
if "%1"=="9" echo           [9] Control de servicios
if "%1"=="10" echo           [10] Crear punto de restauracion
if "%1"=="11" echo           [11] Desinstalar programas
if "%1"=="12" echo           [12] Ver procesos en ejecucion
if "%1"=="13" echo           [13] Ver variables de entorno
if "%1"=="14" echo           [14] Ver estado de la bateria
if "%1"=="15" echo           [15] Liberar espacio en disco
if "%1"=="16" echo           [16] Ver servicios de Windows
if "%1"=="17" echo           [17] Ver informacion de la tarjeta grafica
if "%1"=="18" echo           [18] Control de firewall
if "%1"=="19" echo           [19] Ver eventos del sistema
if "%1"=="20" echo           [20] Ver uso de red
if "%1"=="21" echo           [21] Ver informacion de Wi-Fi
if "%1"=="22" echo           [22] Ver actualizaciones de Windows
if "%1"=="23" echo           [23] Desactivar hibernacion
if "%1"=="24" echo           [24] Crear un punto de restauracion con nombre personalizado
if "%1"=="25" echo           [25] Ver rendimiento del disco duro
if "%1"=="26" echo           [26] Desinstalar una actualizacion de Windows
if "%1"=="27" echo           [27] Ver informacion sobre el sistema de archivos
if "%1"=="28" echo           [28] Desactivar la indexacion de busqueda
if "%1"=="29" echo           [29] Reiniciar el explorador de Windows
if "%1"=="30" echo           [30] Ver los procesos de inicio automatico
if "%1"=="31" echo           [31] Ver los controladores instalados
if "%1"=="32" echo           [32] Monitorear el uso de la CPU en tiempo real
if "%1"=="33" echo           [33] Crear un archivo de volcado de memoria
if "%1"=="34" echo           [34] Ver el estado de los discos (S.M.A.R.T.)
if "%1"=="35" echo           [35] Ver el rendimiento del procesador
if "%1"=="36" echo           [36] Ver la configuracion de proxy
if "%1"=="37" echo           [37] Ver los puertos abiertos
if "%1"=="38" echo           [38] Restaurar un punto de restauracion
if "%1"=="39" echo           [39] Desactivar o activar la aceleracion de hardware
if "%1"=="40" echo           [40] Limpiar el registro de Windows
if "%1"=="41" echo           [41] Generar un informe de red
if "%1"=="42" echo           [42] Activate windows
if "%1"=="43" echo           [43] Desactivar actualizaciones automaticas de Windows
if "%1"=="44" echo           [44] Habilitar actualizaciones automaticas de Windows
if "%1"=="45" echo           [45] Comprobar la version de BIOS
if "%1"=="46" echo           [46] Deshabilitar programas de inicio no deseados
if "%1"=="47" echo           [47] Crear un informe de eventos criticos
if "%1"=="48" echo           [48] Ver uso del disco por carpetas
if "%1"=="49" echo           [49] Mostrar IP publica
if "%1"=="50" echo           [50] Escaneo rapido de malware
if "%1"=="51" echo           [51] Monitor de recursos en tiempo real
if "%1"=="52" echo           [52] Estado del servidor DNS
if "%1"=="53" echo           [53] Buscar controladores desactualizados
if "%1"=="54" echo           [54] Activar modo alto rendimiento
if "%1"=="55" echo           [55] Configurar uso eficiente de energia
if "%1"=="56" echo           [56] Borrar cache de DNS
if "%1"=="57" echo           [57] Ver historial de apagados y reinicios
if "%1"=="58" echo           [58] Desactivar servicios innecesarios
if "%1"=="59" echo           [59] Optimizar memoria virtual
if "%1"=="60" echo           [60] Restaurar configuracion de red a valores predeterminados
exit /b

:: -----------------------------------------------------------------------------------------

:ejecutar_opcion
if "%1"=="1" call :informacion_sistema
if "%1"=="2" call :informacion_adaptador_red
if "%1"=="3" call :reparar_disco
if "%1"=="4" call :estado_red
if "%1"=="5" call :administrador_tareas
if "%1"=="6" call :informacion_almacenamiento
if "%1"=="7" call :monitor_cpu_memoria
if "%1"=="8" call :limpiar_temporales
if "%1"=="9" call :control_servicios
if "%1"=="10" call :crear_punto_restauracion
if "%1"=="11" call :desinstalar_programas
if "%1"=="12" call :ver_procesos
if "%1"=="13" call :ver_variables_entorno
if "%1"=="14" call :estado_bateria
if "%1"=="15" call :limpiar_disco
if "%1"=="16" call :ver_servicios
if "%1"=="17" call :informacion_grafica
if "%1"=="18" call :control_firewall
if "%1"=="19" call :ver_eventos
if "%1"=="20" call :uso_red
if "%1"=="21" call :informacion_wifi
if "%1"=="22" call :actualizaciones_windows
if "%1"=="23" call :desactivar_hibernacion
if "%1"=="24" call :crear_punto_restauracion_personalizado
if "%1"=="25" call :rendimiento_disco
if "%1"=="26" call :desinstalar_actualizacion
if "%1"=="27" call :informacion_sistema_archivos
if "%1"=="28" call :desactivar_indexacion
if "%1"=="29" call :reiniciar_explorador
if "%1"=="30" call :procesos_inicio_automatico
if "%1"=="31" call :ver_controladores
if "%1"=="32" call :monitorear_cpu
if "%1"=="33" call :crear_volcado_memoria
if "%1"=="34" call :estado_smart
if "%1"=="35" call :rendimiento_cpu
if "%1"=="36" call :configuracion_proxy
if "%1"=="37" call :puertos_abiertos
if "%1"=="38" call :restaurar_punto
if "%1"=="39" call :aceleracion_hardware
if "%1"=="40" call :limpiar_registro
if "%1"=="41" call :informe_red
if "%1"=="42" call :abrir_massgrave
if "%1"=="43" call :desactivar_actualizaciones
if "%1"=="44" call :habilitar_actualizaciones
if "%1"=="45" call :version_bios
if "%1"=="46" call :deshabilitar_inicio
if "%1"=="47" call :informe_eventos
if "%1"=="48" call :uso_disco
if "%1"=="49" call :mostrar_ip_publica
if "%1"=="50" call :escaneo_malware
if "%1"=="51" call :monitor_recursos
if "%1"=="52" call :estado_dns
if "%1"=="53" call :controladores_desactualizados
if "%1"=="54" call :modo_alto_rendimiento
if "%1"=="55" call :configurar_energia
if "%1"=="56" call :borrar_cache_dns
if "%1"=="57" call :historial_apagados
if "%1"=="58" call :desactivar_servicios
if "%1"=="59" call :optimizar_memoria_virtual
if "%1"=="60" call :restaurar_red
exit /b

:: ----------------------------------------------------------------------------------------- ::

:cabecera
echo.
echo            ******************************************
echo                        POSEIDON TOOLS - %toolver%       
echo            ******************************************
echo.
exit /b

:: ----------------------------------------------------------------------------------------- ::

:informacion_sistema
cls
call :cabecera
systeminfo
pause
cls
goto menu

:informacion_adaptador_red
cls
call :cabecera
wmic nic get name,netconnectionstatus
pause
cls
goto menu

:reparar_disco
cls
call :cabecera
chkdsk /f
pause
cls
goto menu

:estado_red
cls
call :cabecera
ipconfig /all
pause
cls
goto menu

:administrador_tareas
cls
call :cabecera
start taskmgr
pause
cls
goto menu

:informacion_almacenamiento
cls
call :cabecera
wmic logicaldisk get size,freespace,caption
pause
cls
goto menu

:monitor_cpu_memoria
cls
call :cabecera
wmic cpu get loadpercentage
wmic OS get FreePhysicalMemory,TotalVisibleMemorySize
pause
cls
goto menu

:limpiar_temporales
cls
call :cabecera
del /q /s "%temp%\*" >nul 2>&1
echo Archivos temporales eliminados.
pause
cls
goto menu

:control_servicios
cls
call :cabecera
set /p "servicio=Introduce el nombre del servicio (ejemplo: Spooler): "
set /p "accion=Escribe START para iniciar o STOP para detener el servicio: "
net %accion% %servicio%
pause
cls
goto menu

:crear_punto_restauracion
cls
call :cabecera
echo Creando un punto de restauracion...
powershell -Command "Checkpoint-Computer -Description 'Punto de Restauración Herramientas' -RestorePointType MODIFY_SETTINGS"
echo Punto de restauracion creado.
pause
cls
goto menu

:desinstalar_programas
cls
call :cabecera
echo Abriendo la herramienta de desinstalacion de programas...
start appwiz.cpl
pause
cls
goto menu

:ver_procesos
cls
call :cabecera
tasklist
pause
cls
goto menu

:ver_variables_entorno
cls
call :cabecera
set
pause
cls
goto menu

:estado_bateria
cls
call :cabecera
powercfg /batteryreport
pause
cls
goto menu

:limpiar_disco
cls
call :cabecera
cleanmgr
pause
cls
goto menu

:ver_servicios
cls
call :cabecera
services.msc
pause
cls
goto menu

:informacion_grafica
cls
call :cabecera
wmic path win32_videocontroller get caption
pause
cls
goto menu

:control_firewall
cls
call :cabecera
echo Quieres desactivar el firewall? [Y/N]
set /p "respuesta="
if /i "%respuesta%"=="Y" (
    netsh advfirewall set allprofiles state off
    echo Firewall desactivado.
) else (
    netsh advfirewall set allprofiles state on
    echo Firewall activado.
)
pause
cls
goto menu

:ver_eventos
cls
call :cabecera
eventvwr.msc
pause
cls
goto menu

:uso_red
cls
call :cabecera
netstat -e
pause
cls
goto menu

:informacion_wifi
cls
call :cabecera
netsh wlan show interfaces
pause
cls
goto menu

:actualizaciones_windows
cls
call :cabecera
wuauclt /detectnow
pause
cls
goto menu

:desactivar_hibernacion
cls
call :cabecera
powercfg -h off
echo Hibernacion desactivada.
pause
cls
goto menu

:crear_punto_restauracion_personalizado
cls
call :cabecera
set /p "nombre=Introduce el nombre del punto de restauración: "
powershell -Command "Checkpoint-Computer -Description '%nombre%' -RestorePointType MODIFY_SETTINGS"
echo Punto de restauracion '%nombre%' creado.
pause
cls
goto menu

:rendimiento_disco
cls
call :cabecera
wmic diskdrive get status
pause
cls
goto menu

:desinstalar_actualizacion
cls
call :cabecera
echo Introduce el numero de KB de la actualizacion que deseas desinstalar:
set /p "kb=KB Número: "
wusa /uninstall /kb:%kb%
pause
cls
goto menu

:informacion_sistema_archivos
cls
call :cabecera
fsutil fsinfo volumeinfo C:
pause
cls
goto menu

:desactivar_indexacion
cls
call :cabecera
echo Desactivando la indexación de busqueda...
net stop "Windows Search"
pause
cls
goto menu

:reiniciar_explorador
cls
call :cabecera
taskkill /f /im explorer.exe
start explorer.exe
echo Explorador de Windows reiniciado.
pause
cls
goto menu

:procesos_inicio_automatico
cls
call :cabecera
msconfig
pause
cls
goto menu

:ver_controladores
cls
call :cabecera
driverquery
pause
cls
goto menu

:monitorear_cpu
cls
call :cabecera
wmic cpu get loadpercentage
pause
cls
goto menu

:crear_volcado_memoria
cls
call :cabecera
echo Creando un archivo de volcado de memoria...
tasklist > "%temp%\volcado.txt"
echo Volcado de memoria creado en "%temp%\volcado.txt".
pause
cls
goto menu

:estado_smart
cls
call :cabecera
wmic diskdrive get status
pause
cls
goto menu

:rendimiento_cpu
cls
call :cabecera
wmic cpu get loadpercentage
pause
cls
goto menu

:configuracion_proxy
cls
call :cabecera
netsh winhttp show proxy
pause
cls
goto menu

:puertos_abiertos
cls
call :cabecera
netstat -an
pause
cls
goto menu

:restaurar_punto
cls
call :cabecera
echo Restaurando punto de restauracion...
powershell -Command "Restore-Computer -RestorePointType MODIFY_SETTINGS"
pause
cls
goto menu

:aceleracion_hardware
cls
call :cabecera
echo Desactivando la aceleracion de hardware...
reg add "HKCU\Software\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d "1" /f
pause
cls
goto menu

:limpiar_registro
cls
call :cabecera
echo Limpiando el registro...
regedit /s "C:\ruta\registro.reg"
pause
cls
goto menu

:informe_red
cls
call :cabecera
echo Generando informe de red...
ipconfig > "%temp%\informe_red.txt"
echo Informe guardado en "%temp%\informe_red.txt".
pause
cls
goto menu

:abrir_massgrave
cls
echo Abriendo la web https://massgrave.dev/ en tu navegador predeterminado...
start https://massgrave.dev/
pause
cls
goto menu


:desactivar_actualizaciones
cls
call :cabecera
sc config wuauserv start= disabled
net stop wuauserv
pause
cls
goto menu

:habilitar_actualizaciones
cls
call :cabecera
sc config wuauserv start= auto
net start wuauserv
pause
cls
goto menu

:version_bios
cls
call :cabecera
wmic bios get smbiosbiosversion
pause
cls
goto menu

:deshabilitar_inicio
cls
call :cabecera
start shell:startup
pause
cls
goto menu

:informe_eventos
cls
call :cabecera
eventvwr.msc
pause
cls
goto menu

:uso_disco
cls
call :cabecera
powershell -Command "Get-ChildItem C:\ -Recurse | Sort-Object Length -Descending | Select-Object Name,Length -First 10"
pause
cls
goto menu

:mostrar_ip_publica
cls
call :cabecera
curl ifconfig.me
pause
cls
goto menu

:escaneo_malware
cls
call :cabecera
start mrt
pause
cls
goto menu

:monitor_recursos
cls
call :cabecera
perfmon.exe
pause
cls
goto menu

:estado_dns
cls
call :cabecera
nslookup
pause
cls
goto menu

:controladores_desactualizados
cls
call :cabecera
driverquery
pause
cls
goto menu

:modo_alto_rendimiento
cls
call :cabecera
powercfg -setactive SCHEME_MIN
pause
cls
goto menu

:configurar_energia
cls
call :cabecera
powercfg.cpl
pause
cls
goto menu

:borrar_cache_dns
cls
call :cabecera
ipconfig /flushdns
pause
cls
goto menu

:historial_apagados
cls
call :cabecera
wevtutil qe System /q:"*[System[Provider[@Name='User32'] and (EventID=1074 or EventID=1076)]]" /f:text /c:5
pause
cls
goto menu

:desactivar_servicios
cls
call :cabecera
services.msc
pause
cls
goto menu

:optimizar_memoria_virtual
cls
call :cabecera
sysdm.cpl
pause
cls
goto menu

:restaurar_red
cls
call :cabecera
netsh int ip reset
netsh winsock reset
pause
cls
goto menu

:: Gracias por revisar el código fuente de esta herramienta.
:: Thank you for reviewing the source code of this tool.
:: Merci d'avoir révisé le code source de cet outil.

:: Cualquier sugerencia es aceptada!!
:: Any suggestions are accepted!!
:: Toute suggestion est acceptée !!                                                                                                                     
                                                                                                                        
                             
       
                                                                                                                        
                                                                                                                        
                                                                                                                        
                                                                                                                        
                                                                                                                        
                                                                                                                       