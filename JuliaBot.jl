using Base: Int32, UInt32, UInt64, Cvoid
using Random

# Constants
const PROCESS_ALL_ACCESS = 0x1F0FFF
const TH32CS_SNAPPROCESS = 0x00000002
const TH32CS_SNAPMODULE = 0x00000008
const MAX_PATH = 260

struct PROCESSENTRY32
    dwSize::UInt32
    cntUsage::UInt32
    th32ProcessID::UInt32
    th32DefaultHeapID::UInt64
    th32ModuleID::UInt32
    cntThreads::UInt32
    th32ParentProcessID::UInt32
    pcPriClassBase::Int32
    dwFlags::UInt32
    szExeFile::NTuple{MAX_PATH, UInt8}
end

struct MODULEENTRY32
    dwSize::UInt32
    th32ModuleID::UInt32
    th32ProcessID::UInt32
    GlblcntUsage::UInt32
    ProccntUsage::UInt32
    modBaseAddr::Ptr{Cvoid}
    modBaseSize::UInt32
    hModule::Ptr{Cvoid}
    szModule::NTuple{MAX_PATH, UInt8}
    szExePath::NTuple{MAX_PATH, UInt8}
end

# Windows API function declarations
function OpenProcess(dwDesiredAccess::UInt32, bInheritHandle::Bool, dwProcessId::UInt32)
    ccall((:OpenProcess, "kernel32"), Ptr{Cvoid}, (UInt32, Bool, UInt32), dwDesiredAccess, bInheritHandle, dwProcessId)
end

function ReadProcessMemory(hProcess::Ptr{Cvoid}, lpBaseAddress::Ptr{Cvoid}, lpBuffer::Ptr{Cvoid}, nSize::UInt64, lpNumberOfBytesRead::Ptr{UInt64})
    ccall((:ReadProcessMemory, "kernel32"), Bool, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, UInt64, Ptr{UInt64}), hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
end

function CloseHandle(hObject::Ptr{Cvoid})
    ccall((:CloseHandle, "kernel32"), Bool, (Ptr{Cvoid},), hObject)
end

function CreateToolhelp32Snapshot(dwFlags::UInt32, th32ProcessID::UInt32)
    ccall((:CreateToolhelp32Snapshot, "kernel32"), Ptr{Cvoid}, (UInt32, UInt32), dwFlags, th32ProcessID)
end

function Process32First(hSnapshot::Ptr{Cvoid}, lppe::Ptr{PROCESSENTRY32})
    ccall((:Process32First, "kernel32"), Bool, (Ptr{Cvoid}, Ptr{PROCESSENTRY32}), hSnapshot, lppe)
end

function Process32Next(hSnapshot::Ptr{Cvoid}, lppe::Ptr{PROCESSENTRY32})
    ccall((:Process32Next, "kernel32"), Bool, (Ptr{Cvoid}, Ptr{PROCESSENTRY32}), hSnapshot, lppe)
end

function Module32First(hSnapshot::Ptr{Cvoid}, lpme::Ptr{MODULEENTRY32})
    ccall((:Module32First, "kernel32"), Bool, (Ptr{Cvoid}, Ptr{MODULEENTRY32}), hSnapshot, lpme)
end

function Module32Next(hSnapshot::Ptr{Cvoid}, lpme::Ptr{MODULEENTRY32})
    ccall((:Module32Next, "kernel32"), Bool, (Ptr{Cvoid}, Ptr{MODULEENTRY32}), hSnapshot, lpme)
end

function GetProcessId(processHandle::Ptr{Cvoid})
    ccall((:GetProcessId, "kernel32"), UInt32, (Ptr{Cvoid},), processHandle)
end

# Helper function to convert NTuple to string
function ntuple_to_string(nt::NTuple{MAX_PATH, UInt8})
    str = String([nt[i] for i in 1:MAX_PATH])
    return str[1:findfirst(==('\0'), str)-1] # remove null terminator
end

# Memory reading functions
function read_process_memory(process_handle::Ptr{Cvoid}, address::UInt64, size::Int)
    buffer = Vector{UInt8}(undef, size)
    bytes_read = Ref{UInt64}(0)
    success = ReadProcessMemory(process_handle, Ptr{Cvoid}(address), Ptr{Cvoid}(pointer(buffer)), UInt64(size), Base.unsafe_convert(Ptr{UInt64}, bytes_read))
    if !success
        error("Failed to read process memory")
    end
    return buffer
end

function read_int64(process_handle::Ptr{Cvoid}, address::UInt64)
    buffer = read_process_memory(process_handle, address, 8)
    return reinterpret(Int64, buffer)[1]
end

function read_int32(process_handle::Ptr{Cvoid}, address::UInt64)
    buffer = read_process_memory(process_handle, address, 4)
    return reinterpret(Int32, buffer)[1]
end

# Process functions
function get_process_id_by_name(process_name::String)
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, UInt32(0))
    if snapshot == C_NULL
        error("Failed to create snapshot")
    end

    try
        pe32 = Ref(PROCESSENTRY32(sizeof(PROCESSENTRY32), 0, 0, 0, 0, 0, 0, 0, 0, ntuple(i -> 0x00, MAX_PATH)))
        if !Process32First(snapshot, Base.unsafe_convert(Ptr{PROCESSENTRY32}, pe32))
            error("Failed to get first process")
        end

        while true
            if ntuple_to_string(pe32[].szExeFile) == process_name
                return pe32[].th32ProcessID
            end
            if !Process32Next(snapshot, Base.unsafe_convert(Ptr{PROCESSENTRY32}, pe32))
                break
            end
        end
    finally
        CloseHandle(snapshot)
    end

    error("Process not found")
end

function get_module_base_address(process_handle::Ptr{Cvoid}, module_name::String)
    process_id = GetProcessId(process_handle)
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id)
    if snapshot == C_NULL
        error("Failed to create snapshot")
    end

    try
        me32 = Ref(MODULEENTRY32(sizeof(MODULEENTRY32), 0, 0, 0, 0, Ptr{Cvoid}(0), 0, Ptr{Cvoid}(0), ntuple(i -> 0x00, MAX_PATH), ntuple(i -> 0x00, MAX_PATH)))
        if !Module32First(snapshot, Base.unsafe_convert(Ptr{MODULEENTRY32}, me32))
            error("Failed to get first module")
        end

        while true
            if ntuple_to_string(me32[].szModule) == module_name
                return UInt64(me32[].modBaseAddr)
            end
            if !Module32Next(snapshot, Base.unsafe_convert(Ptr{MODULEENTRY32}, me32))
                break
            end
        end
    finally
        CloseHandle(snapshot)
    end

    error("Module not found")
end


# Keyboard input (basic implementation, might need refinement)
const VK_SHIFT = 0x10

function GetAsyncKeyState(vKey::UInt32)
    ccall((:GetAsyncKeyState, "user32"), Int16, (UInt32,), vKey)
end

function is_key_pressed()
    return (GetAsyncKeyState(UInt32(VK_SHIFT)) & 0x8000) != 0
end


# Mouse
function mouse_event_wrapper(dwFlags,dx,dy,dwData,dwExtraInfo)
    ccall((:mouse_event, "User32"),stdcall,Nothing,(UInt32,UInt32,UInt32,UInt32,UInt),dwFlags,dx,dy,dwData,dwExtraInfo)
end

function click()
    sleep(rand(0.01:0.001:0.03))
    mouse_event_wrapper(0x2,0,0,0,0) # press left mouse
    sleep(rand(0.01:0.001:0.05))
    mouse_event_wrapper(0x4,0,0,0,0) # release left mouse
end


# Offsets
const dwEntityList = 0x1969668
const dwLocalPlayerPawn = 0x17D47E0
const m_iIDEntIndex = 0x13A8
const m_iTeamNum =0x3C3
const m_iHealth = 0x324

# Main function to demonstrate usage
function main()
    print("🚀 JuliaBot is running...")
    process_name = "cs2.exe"
    process_id = get_process_id_by_name(process_name)
    process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id)

    if process_handle == C_NULL
        error("Failed to open process")
    end

    while true
        try
            module_name = "client.dll"
            base_address = get_module_base_address(process_handle, module_name)
            
            if is_key_pressed()
                player_base = read_int64(process_handle, base_address + dwLocalPlayerPawn)
                entityId = read_int32(process_handle, UInt64(player_base + m_iIDEntIndex))

                if entityId > 0
                    entList = read_int64(process_handle, base_address + dwEntityList)

                    entEntry = read_int64(process_handle, entList + 0x8 * (UInt64(entityId) >> 9) + 0x10)
                    entity = read_int64(process_handle, entEntry + 120 * (UInt64(entityId) & 0x1FF))

                    entityTeam = read_int32(process_handle, entity + UInt64(m_iTeamNum))
                    playerTeam = read_int32(process_handle, player_base + UInt64(m_iTeamNum))

                    if entityTeam != playerTeam
                        entityHp = read_int32(process_handle, UInt64(entity) + m_iHealth)

                        if entityHp > 0
                            click()
                        end
                    end
                end

                sleep(0.03)

            else
                sleep(0.1)
            end

        catch e
            if e isa InterruptException
                break
            end
            if e isa Exception
                println("error: $e")
            end

        end
    end
end


main()
