import ctypes
import time
import threading
import os
import datetime


tiempo_descarga_registros = 0
global time_sleep_time
time_sleep_time = 1


#  pyinstaller --onefile --clean prueba_crosschex_v5.py

# Importa las variables de la biblioteca tc-b_new_sdk.dll
dll_path = os.path.abspath("tc-b_new_sdk.dll")
sdk = ctypes.CDLL(dll_path)

# Variables de configuración
ip_addr = "192.168.1.142"
port = 5010


class CCHEX_UDP_SEARCH_STRU(ctypes.Structure):
    _fields_ = [
        ("DevType", ctypes.c_ubyte * 10),
        ("DevSerialNum", ctypes.c_ubyte * 16),
        ("IpAddr", ctypes.c_ubyte * 4),
        ("IpMask", ctypes.c_ubyte * 4),
        ("GwAddr", ctypes.c_ubyte * 4),
        ("MacAddr", ctypes.c_ubyte * 6),
        ("ServAddr", ctypes.c_ubyte * 4),
        ("Port", ctypes.c_uint16 * 2),
        ("NetMode", ctypes.c_ubyte),
        ("Version", ctypes.c_ubyte * 8),
        ("Reserved", ctypes.c_ubyte * 4)
    ]

class CCHEX_UDP_SEARCH_STRU_EXT_INF(ctypes.Structure):
    _fields_ = [
        ("Data", ctypes.c_ubyte * 167),
        ("Padding", ctypes.c_ubyte),        
        ("Result", ctypes.c_int32),
        ("MachineId", ctypes.c_uint32),
        ("DevHardwareType", ctypes.c_int32)
    ]

class CCHEX_UDP_SEARCH_ALL_STRU_EXT_INF(ctypes.Structure):
    _fields_ = [
        ("DevNum", ctypes.c_int32),
        ("dev_net_info", CCHEX_UDP_SEARCH_STRU_EXT_INF * 16)
    ]

class CchexHandle(ctypes.Structure):
    _fields_ = [("handle", ctypes.c_void_p)]

class CCHEX_DOWNLOAD_RECORD_INFO(ctypes.Structure):
    _fields_ = [
        ("MachineId", ctypes.c_uint32),          # 4 bytes, Device ID
        ("NewRecordFlag", ctypes.c_ubyte),       # 1 byte, new record or not
        ("EmployeeId", ctypes.c_ubyte * 5),      # 5 bytes, User ID
        ("Date", ctypes.c_uint32),               # 4 bytes, Time (number of seconds since 2000.1.2)
        ("BackId", ctypes.c_ubyte),              # 1 byte, Backup ID
        ("RecordType", ctypes.c_ubyte),          # 1 byte, Record Type
        ("WorkType", ctypes.c_ubyte * 3),        # 3 bytes, Work Code
        ("Rsv", ctypes.c_ubyte),                 # 1 byte, Reserved
    ]

class CCHEX_RET_RECORD_INFO_STRU(ctypes.Structure):
    _fields_ = [
        ("MachineId", ctypes.c_uint32),           # Machine ID, unsigned 32 bits
        ("NewRecordFlag", ctypes.c_ubyte),        # New record flag, 1 byte
        ("EmployeeId", ctypes.c_ubyte * 5),       # Employee ID, 5 bytes
        ("Date", ctypes.c_ubyte * 4),             # Date, 4 bytes
        ("BackId", ctypes.c_ubyte),               # Backup ID, 1 byte
        ("RecordType", ctypes.c_ubyte),           # Record type, 1 byte
        ("WorkType", ctypes.c_ubyte * 3),         # Work type, 3 bytes
        ("Rsv", ctypes.c_ubyte),                  # Reserved, 1 byte
        ("CurIdx", ctypes.c_uint32),              # Current index, unsigned 32 bits
        ("TotalCnt", ctypes.c_uint32)             # Total count, unsigned 32 bits
    ]

class CCHEX_RET_CLINECT_CONNECT_TYPE(ctypes.Structure):
    _fields_ = [
        ("Result", ctypes.c_int),
        ("Addr", ctypes.c_char * 24)
    ]

class CCHEX_RET_MSGADDNEW_UNICODE_INFO_TYPE(ctypes.Structure):
    _fields_ = [
        ("DevIdx", ctypes.c_int),
        ("MachineId", ctypes.c_uint32),
        ("Addr", ctypes.c_char * 24),
        ("Version", ctypes.c_char * 8),
        ("DevType", ctypes.c_char * 8),
        ("DevTypeFlag", ctypes.c_int)
    ]

class CCHEX_RET_DEV_LOGIN_STRU(ctypes.Structure):
    _fields_ = [
        ("DevIdx", ctypes.c_int),                 # Índice del dispositivo (4 bytes, signed)
        ("MachineId", ctypes.c_uint32),          # ID del dispositivo (4 bytes, unsigned)
        ("Addr", ctypes.c_ubyte * 24),           # Dirección IP y puerto (24 bytes, array de bytes)
        ("Version", ctypes.c_ubyte * 8),         # Versión (8 bytes, array de bytes)
        ("DevType", ctypes.c_ubyte * 8),         # Tipo de dispositivo (8 bytes, array de bytes)
        ("DevTypeFlag", ctypes.c_uint32)         # Bandera del tipo de dispositivo (4 bytes, unsigned)
    ]

BUFFER_SIZE = 32000
pBuff = (ctypes.c_ubyte * BUFFER_SIZE)()
dev_idx = (ctypes.c_int * 1)(0)
Type = (ctypes.c_int * 1)(0)

global ipAddrBytes
ipAddrBytes = ctypes.c_ubyte * 4

global registros
registros = []


sdk.CChex_Init.restype = None
sdk.CChex_Init.argtypes = []
sdk.CChex_Init()

# Crear el handle con parámetros de servicio
iscloseservice = 1  # Ajusta según tu configuración
service_port = 5010  # Ajusta según tu configuración
sdk.CChex_Start_With_Param.argtypes = [ctypes.c_ushort, ctypes.c_ushort]
sdk.CChex_Start_With_Param.restype = ctypes.c_void_p  # Si devuelve un handle
anviz_handle = ctypes.c_void_p(sdk.CChex_Start_With_Param(iscloseservice, service_port))
print("anviz_handle:", anviz_handle)


# Verificar si el handle es válido
if anviz_handle.value == 0:
    print("Error: El handle no es válido. Verifica la llamada a CChex_Start_With_Param.")
else:
    print(f"Handle inicializado correctamente: {anviz_handle.value}")


# Función para buscar dispositivos UDP
def udp_search():
    print("Buscando dispositivos en la red...")
    sdk.CCHex_Udp_Search_Dev.restype = ctypes.c_int  # La función devuelve un int (éxito o fallo)
    sdk.CCHex_Udp_Search_Dev.argtypes = [ctypes.c_void_p]  # Recibe el handle como argumento
    ret = sdk.CCHex_Udp_Search_Dev(anviz_handle)
    if ret > 0:       
        # Ahora podemos llamar a CChex_Update
        timer_tick()
    else:
        # Llamar de nuevo después de un intervalo
        threading.Timer(2, udp_search).start()



def connect_to_client():
    global ip_addr, port
    sdk.CCHex_ClientConnect.restype = ctypes.c_int  # La función devuelve un int (resultado)
    sdk.CCHex_ClientConnect.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]  # Tipos de argumentos
    global ipAddrBytes
    ip_bytes = (ctypes.c_ubyte * 4)(*map(int, ip_addr.split('.')))
    try:
        # Convertir IP a string
        ip_str = str(ip_addr)
        # Convertir puerto a string
        port_str = str(port)

        if len(ip_str) > 15:
            raise ValueError("La dirección IP es demasiado larga.")
        
        # Convertir IP a formato bytes (16 bytes de longitud, rellenados con ceros al final)
        ip_array = (ctypes.c_ubyte * 16)(*ip_str.encode('utf-8').ljust(16, b'\x00'))
        
        # Validar el puerto
        if not (0 <= port <= 65535):
            raise ValueError("El puerto debe estar entre 0 y 65535.")
        
        # Llamar a la función de conexión
        ret = sdk.CCHex_ClientConnect(anviz_handle, ip_array, port)
        
        if ret > 0:
            print(f"Conexión exitosa al dispositivo: {ip_str}:{port_str}")
            timer_tick()
        else:
            print(f"Error en la conexión: código {ret}")
    
    except Exception as e:
        print(f"Error al intentar conectar: {e}")


def download_all_new_records():
    print("Buscando nuevos registros...")
    sdk.CChex_DownloadAllNewRecords.restype = ctypes.c_int  # La función devuelve un int
    sdk.CChex_DownloadAllNewRecords.argtypes = [ctypes.c_void_p, ctypes.c_int]  # Recibe el handle, el índice y el buffer de 32000 bytes
    print("dev_idx[0]:", dev_idx[0])
    ret = sdk.CChex_DownloadAllNewRecords(anviz_handle, dev_idx[0])
    if ret > 0:
        #print("Dispositivos encontrados. Procediendo con la consulta de datos...")
        print("Aquí deberían ir los registros...")
        
        # Ahora podemos llamar a CChex_Update
        timer_tick()
    else:
        print("No se encontraron dispositivos. Intentando nuevamente...")
        # Llamar de nuevo después de un intervalo
        threading.Timer(2, download_all_new_records).start()


def parse_device_info(pBuff):
    # Leer el número de dispositivos del buffer (primeros 4 bytes)
    dev_num = ctypes.cast(ctypes.byref(pBuff), ctypes.POINTER(ctypes.c_int32)).contents.value

    if dev_num <= 0:
        print("No devices found.")
        return []

    # Crear una lista para almacenar la información de los dispositivos
    devices = []

    # Calcular el tamaño de la estructura de dispositivo
    device_info_size = ctypes.sizeof(CCHEX_UDP_SEARCH_STRU_EXT_INF)

    # Iterar sobre cada dispositivo
    for i in range(dev_num):
        # Calcular el offset dentro del buffer
        offset = 4 + (i * device_info_size)  # 4 bytes para DevNum + cada estructura

        # Obtener un puntero a la estructura del dispositivo en el offset
        device_ptr = ctypes.cast(ctypes.addressof(pBuff) + offset, ctypes.POINTER(CCHEX_UDP_SEARCH_STRU_EXT_INF))
        device_info = device_ptr.contents

        # Procesar información del dispositivo
        devices.append({
            "MachineId": device_info.MachineId,
            "Result": device_info.Result,
            "DevHardwareType": device_info.DevHardwareType,
        })

    return devices


# Función que se ejecuta periódicamente para realizar la consulta
def timer_tick():

    pBuff = (ctypes.c_ubyte * BUFFER_SIZE)()
    Type = (ctypes.c_int * 1)(0)
    ret = sdk.CChex_Update(anviz_handle, dev_idx, Type, ctypes.cast(pBuff, ctypes.c_void_p), len(pBuff))
    print("dev_idx: ", dev_idx[0])
    if ret > 0:
        print("CChex_Update ejecutado con éxito.")
        print(f"Msg Type: {Type[0]}")
        if Type[0] == 48:
            result = CCHEX_UDP_SEARCH_ALL_STRU_EXT_INF.from_buffer(pBuff)
            if result.DevNum > 0:
                print(f"Dispositivos encontrados: {result.DevNum}")
                for i in range(result.DevNum):
                    device_info = result.dev_net_info[i]

                    # Supongamos que ya tienes pBuff (como ctypes.c_char_Array) y DevNum fue encontrado

                    print(f"Dispositivo {i+1}:")
                    print(f"  Device ID: {device_info.MachineId}")
                    print(f"  Result: {device_info.Result}")
                    print(f"  Device Hardware Type: {device_info.DevHardwareType}")
                    
                                        
                    data_buffer = device_info.Data
                    device_data = CCHEX_UDP_SEARCH_STRU.from_buffer(data_buffer)
                    devices = []

                    dev_type = device_data.DevType
                    dev_serial_num = device_data.DevSerialNum

                    global ipAddrBytes
                    ipAddrBytes = device_data.IpAddr

                    ip_addr = ".".join(str(ctypes.c_ubyte(device_data.IpAddr[i]).value) for i in range(4))  # 4 bytes de IP #device_data.IpAddr
                    ip_mask = ".".join(str(ctypes.c_ubyte(device_data.IpMask[i]).value) for i in range(4))
                    gw_addr = ".".join(str(ctypes.c_ubyte(device_data.GwAddr[i]).value) for i in range(4))
                    mac_addr = ".".join(str(ctypes.c_ubyte(device_data.MacAddr[i]).value) for i in range(6))
                    serv_addr = ".".join(str(ctypes.c_ubyte(device_data.ServAddr[i]).value) for i in range(4))
                    port = device_data.Port[0]
                    net_mode = device_data.NetMode
                    version = device_data.Version
                    reserved = device_data.Reserved

                    # Almacenar la información del dispositivo en un diccionario
                    devices.append({
                        "MachineId": device_info.MachineId,
                        "Result": device_info.Result,
                        "DevHardwareType": device_info.DevHardwareType,
                        "DevType": dev_type,
                        "DevSerialNum": dev_serial_num,
                        "IpAddr": ip_addr,
                        "IpMask": ip_mask,
                        "GwAddr": gw_addr,
                        "MacAddr": mac_addr,
                        "ServAddr": serv_addr,
                        "Port": port,
                        "NetMode": net_mode,
                        "Version": version,
                        "Reserved": reserved,
                    })

                    # Imprimir la información del dispositivo
                    for device in devices:
                        print("Datos del dispositivo:")
                        print("MachineId:", device["MachineId"])
                        print("Result:", device["Result"])
                        print("DevHardwareType:", device["DevHardwareType"])
                        print("DevType:", device["DevType"])
                        print("DevSerialNum:", device["DevSerialNum"])
                        print("IpAddr:", device["IpAddr"])
                        print("IpMask:", device["IpMask"])
                        print("GwAddr:", device["GwAddr"])
                        print("MacAddr:", device["MacAddr"])
                        print("ServAddr:", device["ServAddr"])
                        print("Port:", device["Port"])
                        print("NetMode:", device["NetMode"])
                        print("Version:", device["Version"])
                        print("Reserved:", device["Reserved"])
                
            else:
                print("No se encontraron dispositivos.")
        elif Type[0] == 2:
            # Interpretar la estructura devuelta
            dev_info = CCHEX_RET_DEV_LOGIN_STRU.from_buffer_copy(pBuff)
            
            # Crear representación como cadena
            info_buff = (
                f"Dev Login --- [MachineId: {dev_info.MachineId} "
                f"Version: {bytes(dev_info.Version).decode('utf-8').rstrip(chr(0))} "
                f"DevType: {bytes(dev_info.DevType).decode('utf-8').rstrip(chr(0))} "
                f"Addr: {bytes(dev_info.Addr).decode('utf-8').rstrip(chr(0))}]"
            )
            print(info_buff + f"    DevTypeFlag (hex): {hex(dev_info.DevTypeFlag)}")
            
            # Simular lista de dispositivos y agregar la información
            device_list = []  # Esto representaría `listViewDevice` en C#
            device_item = {
                "MachineId": dev_info.MachineId,
                "DevIdx": dev_info.DevIdx,
                "Addr": bytes(dev_info.Addr).decode('utf-8').rstrip(chr(0)),
                "Version": bytes(dev_info.Version).decode('utf-8').rstrip(chr(0)),
            }
            device_list.append(device_item)
            
            # Contar dispositivos
            DevCount = len(device_list)
            print(f"Dispositivo agregado. Total de dispositivos: {DevCount}")
            
            # Actualizar el título del grupo (simulado)
            group_box_title = f"Dispositivo:({DevCount})"
            print(group_box_title)
            
            # Crear un diccionario para mapear DevIdx a DevTypeFlag
            DevTypeFlag = {}
            DevTypeFlag[dev_info.DevIdx] = dev_info.DevTypeFlag

            # Mostrar la lista de dispositivos
            print("Lista de dispositivos:")
            for device in device_list:
                print(device)

        elif Type[0] == 71:
            global time_sleep_time
            time_sleep_time = 0.01
            global registros
            record_info = CCHEX_RET_RECORD_INFO_STRU.from_buffer(pBuff)
            machine_id = record_info.MachineId
            new_record_flag = record_info.NewRecordFlag
            employee_id = int.from_bytes(record_info.EmployeeId, byteorder='big', signed=False)
            #employee_id = bytes(record_info.EmployeeId).decode('ascii').rstrip('\x00')  # Convertir a string si es ASCII
            seconds_since_epoch = int.from_bytes(record_info.Date, byteorder='big', signed=False)
            # Fecha de referencia: 2000-01-02
            base_date = datetime.datetime(2000, 1, 2)
            calculated_date = base_date + datetime.timedelta(seconds=seconds_since_epoch)
            _registro = [machine_id, new_record_flag, employee_id, calculated_date]
            registros.append(_registro)
            print(f"Machine ID: {machine_id}, New Record: {new_record_flag}, Employee ID: {employee_id}, Date: {calculated_date}")
    else:
        print("No se obtuvo respuesta. Reintentando...")
        # Aquí podrías agregar alguna lógica de reintentos o hacer algo si no hay respuesta

    # Volver a ejecutar el timer
    threading.Timer(2, timer_tick).start()  # Vuelve a llamar a esta función cada 2 segundos

udp_search()

# Esto mantendrá la aplicación corriendo y ejecutando el código periódicamente
while True:
    tiempo_descarga_registros += 1
    if tiempo_descarga_registros == 10:
        print("Conectando al cliente...")
        print("dev_idx:", dev_idx)
        connect_to_client()
    elif tiempo_descarga_registros == 15:
        print("Descargando registros...")
        print("dev_idx:", dev_idx)
        download_all_new_records()
        #tiempo_descarga_registros = 0
    elif tiempo_descarga_registros < 15:
        print("Tiempo restante para descarga de registros:", 15 - tiempo_descarga_registros)
    else:
        time_sleep_time = 1
    time.sleep(time_sleep_time)  # Mantener el proceso activo (no termina inmediatamente)