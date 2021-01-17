/// 
/// 
/// 
/// Calls device installation functions (SetupDiXxx functions) to find and identify a HID collection.
/// https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetclassdevsw
/// 
/// https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinterfacedetaila
/// 
/// Calls CreateFile to open a file on a HID collection.
///
/// https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
/// 
/// Calls HidD_Xxx HID support routines to obtain a HID collection's preparsed data and information about the HID collection.
///
/// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/hidsdi/nf-hidsdi-hidd_getpreparseddata
/// 
/// Calls ReadFile to read input reports.
///
/// https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
/// 
/// Calls HidP_Xxx HID support routines to interpret HID reports.
/// 
/// 


// TO DO
//
// Create Read loop to continue to get input reports
// Read async
// Create Result type?
// Controller struct
// Wrap FFI functions into rust with Result<Foo, Bar>
// Clean up code
// Move to libstick and tie to events


use std::ptr;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::fmt::{Debug, Display, self};

type Void = std::ffi::c_void;
type WcharT = u16;
type DWord = u32;
// https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types
type Bool = std::os::raw::c_int;
type Boolean = std::os::raw::c_uchar;
type Long = std::os::raw::c_long;
type ULong = std::os::raw::c_ulong;
type NTStatus = Long;

#[derive(Debug)]
enum SomethingSomething
{
    WinError(String),
    Other(String),
    ParseError(std::string::FromUtf8Error),
}

impl Display for SomethingSomething
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        write!(f, "yee")
    }
}

impl From<std::string::FromUtf8Error> for SomethingSomething
{
    fn from(error: std::string::FromUtf8Error) -> Self
    {
        SomethingSomething::ParseError(error)
    }
}


#[repr(C)]
#[derive(Debug)]
struct GUID
{
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8]
}

#[repr(C)]
struct SP_DEVICE_INTERFACE_DETAIL_DATA_A
{
    cb_size: u32,
    // MAX_PATH = 256 bytes thus it cant exceed this. Needs a way to proper fitted
    device_path: [u8; 256],
}

#[repr(C)]
struct SP_DEVICE_INTERFACE_DATA
{
    cb_size: DWord,
    interface_class_guid: GUID,
    flags: DWord,
    reserved: usize,
}

#[repr(C)]
struct SECURITY_ATTRIBUTES
{
    n_length: DWord,
    lp_security_descriptor: *mut Void,
    b_inherit_handle: Bool
}

#[repr(C)]
struct _HIDD_ATTRIBUTES
{
    size: u32,
    vendor_id: u16,
    product_id: u16,
    version_number: u16,

}

enum _HidpPreparsedData
{}

#[repr(C)]
#[derive(Debug)]
struct HIDP_CAPS
{
    usage_id: u16,
    usage_page: u16,
    input_report_byte_length: u16,
    output_report_byte_length: u16,
    feature_report_byte_length: u16,
    reserved: [u16; 17],
    number_link_collection_nodes: u16,
    number_input_button_caps: u16,
    number_input_value_caps: u16,
    number_input_data_indices: u16,
    number_output_data_caps: u16,
    number_output_value_caps: u16,
    number_output_data_indicies: u16,
    number_feature_data_caps: u16,
    number_feature_value_caps: u16,
    number_feature_data_indicies: u16,
}

impl _HIDD_ATTRIBUTES
{
    fn _as_mut_ptr(&mut self) -> *mut _HIDD_ATTRIBUTES
    {
        self
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
struct HIDP_DATA
{
    data_index: u16,
    reserved: u16,
    data: HIDP_DATA_VALUE
}

#[repr(C)]
#[derive(Clone, Copy)]
union HIDP_DATA_VALUE
{
    raw_value: std::os::raw::c_int,
    on: bool,
}

// no clue how to implement debug for unions, though might not be necessary if 
impl std::fmt::Debug for HIDP_DATA_VALUE
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe
        {
            match &self
            {
                HIDP_DATA_VALUE { raw_value: v} => f.write_str(&format!("{}", v)),
            }
        }
    }

}

struct HidDevice
{
    device_path: Vec<u16>,
    hid_device_handle: *mut Void,
    caps: HIDP_CAPS,
    preparsed_data: *mut Void,
}

// Do we use this considering the C type is u32?
#[repr(C)]
enum _HIDP_REPORT_TYPE
{
    HidPInput = 0,
    HidPOutput = 1,
    HidPFeature = 2,
}

fn main() -> Result<(), SomethingSomething>
{
    // Get the Hid (human interface devices) guid from win32 call
    let mut hid_guid = std::mem::MaybeUninit::<GUID>::uninit();
    unsafe { HidD_GetHidGuid(hid_guid.as_mut_ptr())};

    //Check is macro for GetLastError() with string to know where it errors, will be replaced with safe rust wrap around unsafe call
    Check!("HidD_GetHidGuid");

    let device_info_list_handle = unsafe { SetupDiGetClassDevsW(
        hid_guid.as_ptr(), 
        ptr::null_mut(), 
        ptr::null_mut(), 
        0x00000004 | 0x00000002 | 0x00000010) };
    Check!("SetupDiGetClassDevsW");


    //  Enum interface stuff

    let mut interface_data = Vec::new();

    let mut member = 0u32;

    // Run until SetupDiEnumDeviceInterfaces returns false, which indicates there are no more devices in the enum
    // Get last error returns 87, invalid parameter as outside of range
    loop {    
        let mut data = SP_DEVICE_INTERFACE_DATA{
            cb_size: std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as DWord,
            interface_class_guid: GUID { data1: 0, data2: 0, data3: 0, data4: [0,0,0,0,0,0,0,0]},
            flags: 0x00000001,
            reserved: 0,
        };
        let p_data: *mut SP_DEVICE_INTERFACE_DATA = &mut data;
        let success = unsafe { SetupDiEnumDeviceInterfaces(device_info_list_handle, std::ptr::null_mut(), hid_guid.as_ptr(), member, p_data as *mut Void)};
		if 0 == success {
			break;
		}
        Check!("SetupDiEnumDeviceInterfaces");
        interface_data.push(data);
        member += 1;
    }

    let mut _devices: Vec<HidDevice> = Vec::with_capacity(interface_data.len() as usize);

    println!("Ammount of interfaces in SetupDiEnumDeviceInterfaces: {}", interface_data.len());

    for i in 0..interface_data.len()
    {
        let p_interface_data: *mut SP_DEVICE_INTERFACE_DATA = &mut interface_data[i];
        
        if let Ok(data) = setup_di_get_device_interface_detail_a(device_info_list_handle, p_interface_data as *mut Void)
        {
        let n = String::from_utf8(data.device_path.to_vec())?;

        let n_ref = n.trim_matches('\u{0}');
        
        let filename = to_wide_string(n_ref);

        //Create handle from device_path to use for calls
        let valid_device_handle = create_file_w(
            filename.as_ptr(), //filename
            0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
            0x00000001 | 0x00000002, // FILE_SHARE_READ | FILE_SHARE_WRITE
            std::ptr::null_mut(), // Default security
            3, // OPEN_EXISTING
            0, //
            std::ptr::null_mut() // No template necessary
        );
        
        if let Ok(valid_device_handle) = valid_device_handle
        {
            // Error 5 Error_access_Denied -> Access is denied
            // Error 32 Error Sharing Violation -> Process being used by another process

            if let Ok(preparsed_data) = hid_get_preparsed_data(valid_device_handle)
            {

                let mut capabilities = std::mem::MaybeUninit::<HIDP_CAPS>::uninit();

                unsafe { HidP_GetCaps(preparsed_data, capabilities.as_mut_ptr() as *mut Void) };
                Check!("Get Caps");
                let caps = unsafe { capabilities.assume_init() };

                let device = HidDevice {caps, hid_device_handle: valid_device_handle, preparsed_data, device_path: filename};

                if device.caps.usage_id == 5
                {                
                    println!("{:?}", read_data(&device)?);
                }
            }
            else
            {
                Check!("Get Preparsed data");
            }
            unsafe { CloseHandle(valid_device_handle)};
        }
    }
    }
    unsafe { hid_guid.assume_init() };
    unsafe { SetupDiDestroyDeviceInfoList(device_info_list_handle) };

    Ok(())
}

fn read_data(device: &HidDevice) -> Result<Vec<HIDP_DATA>,SomethingSomething>
{
    unsafe {HidD_FlushQueue(device.hid_device_handle);}

    let mut report_buffer = vec![0u8; device.caps.input_report_byte_length as usize];
    let mut bytesread = 0;
    let p_bytes_read: *mut u32 = &mut bytesread;

    if unsafe { 0 == ReadFile(device.hid_device_handle, report_buffer.as_mut_ptr() as *mut Void, device.caps.input_report_byte_length as u32, p_bytes_read, std::ptr::null_mut())}
    {
        Check!("readfile");
    }


    //Might not be needed since it seems to be the same as caps.number_input_data_indices
    let max_data = unsafe { HidP_MaxDataListLength(0, device.preparsed_data) };
    let p_max_data: *const u32 = &max_data;
    let mut data_buffer = vec![HIDP_DATA {data_index: 0, reserved: 0, data: HIDP_DATA_VALUE { on: true} }; max_data as usize];
    
    // Maybe bad FFI buffer, return value of button in the on state (0) wierd
    unsafe { HidP_GetData(0, data_buffer.as_mut_ptr() as *mut Void, p_max_data, device.preparsed_data, report_buffer.as_mut_ptr() as *mut Void, device.caps.input_report_byte_length as u32)};
    Ok(data_buffer)
}


fn to_wide_string(string: &str) -> Vec<u16> 
{
    let v: Vec<u16> = OsStr::new(string)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect();
    v
}

/// Returns a pointer to preparsed data of the given device handle.
/// Preparsed data is an opaque C struct we retrieve from win32 api.
/// This data is necessary for other win32 functions.
fn hid_get_preparsed_data(device_handle: *mut Void) -> Result<*mut Void, SomethingSomething>
{
    let mut preparsed_data: *mut Void = std::ptr::null_mut();
    let p_preparsed_data: *mut *mut Void = &mut preparsed_data;

    if unsafe { 0 == HidD_GetPreparsedData(device_handle, p_preparsed_data) }
    {
        let windows_error = unsafe { GetLastError() };
        return Err(SomethingSomething::WinError(windows_error.to_string()));
    }
    Ok(preparsed_data)
}


fn create_file_w(
    lp_file_name: *const WcharT,
    dw_desired_access: DWord,
    dw_share_mode: DWord,
    lp_security_attributes: *const SECURITY_ATTRIBUTES,
    dw_creation_disposition: DWord,
    dw_flags_and_attributes: DWord,
    h_template_file: *mut Void,
) -> Result<*mut Void, SomethingSomething>
{
    let expected_errors = [0];
    let handle = unsafe { CreateFileW(lp_file_name, dw_desired_access, dw_share_mode, lp_security_attributes, dw_creation_disposition, dw_flags_and_attributes, h_template_file) };

    let windows_error = unsafe { GetLastError() };

    if expected_errors.contains(&windows_error)
    {
        return Ok(handle)
    }
    else
    {
        let win_err = format!("windows error: {}, at create_file_w", windows_error);
        return Err(SomethingSomething::WinError(win_err))
    }

}


fn setup_di_get_device_interface_detail_a(
    device_info_list_handle: *mut Void, 
    p_interface_data: *mut Void, 
) -> Result<SP_DEVICE_INTERFACE_DETAIL_DATA_A, SomethingSomething>
{
    let mut required_size = 0u32;
    let p_required_size: *mut u32 = &mut required_size;

    unsafe { SetupDiGetDeviceInterfaceDetailA(
        device_info_list_handle, 
        p_interface_data as *mut Void,
        std::ptr::null_mut(), 
        0, 
        p_required_size, 
        std::ptr::null_mut()) };
    
    let windows_error = unsafe { GetLastError() };
    if windows_error != 122
    {
        let error_line = line!();
        let win_err = format!("Windows Error: {} at line: {}", windows_error, error_line);
        return Err(SomethingSomething::WinError(win_err))
    }

    let mut data = SP_DEVICE_INTERFACE_DETAIL_DATA_A { cb_size: 8 as u32, device_path: [0;256]};

    let p_data: *mut SP_DEVICE_INTERFACE_DETAIL_DATA_A = &mut data;

    if unsafe { 0 == SetupDiGetDeviceInterfaceDetailA(
        device_info_list_handle, 
        p_interface_data as *mut Void,
        p_data as *mut Void, 
        required_size, 
        p_required_size, 
        std::ptr::null_mut()) }
    {
        let windows_error = unsafe { GetLastError() };
        if windows_error != 122
        {
            let error_line = line!();
            let win_err = format!("Windows Error: {} at line: {}", windows_error, error_line);
            return Err(SomethingSomething::WinError(win_err))
        }
    }
    
    Ok(data)
}


#[link(name="SetupApi")]
extern "system"
{
    fn SetupDiGetDeviceInterfaceDetailA(
        DeviceInfoSet: *mut Void, 
        DeviceInterfaceData: *mut Void, 
        DeviceInterfaceDetailData: *mut Void,
        DeviceInterfaceDetailDataSize: DWord,
        RequiredSize: *const DWord,
        DeviceInfoData: *mut Void,
    ) -> Bool;

    fn SetupDiEnumDeviceInterfaces(
        DeviceInfoSet: *mut Void,
        DeviceInfoData: *mut Void,
        InterfaceClassGuid: *const GUID,
        MemberIndex: DWord,
        DeviceInterfaceData: *mut Void,
    ) -> Bool;



    // Returns Dev info set handle
    fn SetupDiGetClassDevsW(classguid: *const GUID, enumerator: *const WcharT, hwnd_parent: *mut Void, flags: DWord) -> *mut Void;
    
    // handle is a Device Info Set Handle
    // Destroy Dev info set to free up resources
    fn SetupDiDestroyDeviceInfoList(handle: *const Void) -> Bool;
}

#[link(name = "kernel32")]
extern "system"
{
    fn CloseHandle(handle: *const Void) -> Bool;

    fn CreateFileW(
        lp_file_name: *const WcharT,
        dw_desired_access: DWord,
        dw_share_mode: DWord,
        lp_security_attributes: *const SECURITY_ATTRIBUTES,
        dw_creation_disposition: DWord,
        dw_flags_and_attributes: DWord,
        h_template_file: *mut Void,
    ) -> *mut Void;

    fn ReadFile(
        h_file: *const Void,
        lp_buffer: *const Void,
        n_number_of_bytes_to_read: DWord,
        lp_number_of_byte_read: *const DWord,
        lp_overlapped: *const Void,
    ) -> Bool;

    fn GetLastError() -> DWord;
}

#[link(name="hid")]
extern "system"
{
    fn HidD_GetHidGuid(HidGuid: *mut GUID);

    fn _HidD_GetPhysicalDescriptor(HidDeviceObject: *const Void, Buffer: *mut Void, BufferLength: u32) -> Boolean;

    fn _HidD_GetAttributes(HidDeviceObject: *const Void, Attributes: *mut _HIDD_ATTRIBUTES) -> Boolean;

    fn HidD_GetPreparsedData(HidDeviceObject: *const Void, PHIDP_PREPARSED_DATA: *mut *mut Void) -> Boolean;

    fn _HidD_FreePreparsedData(PHIDP_PREPARSED_DATA: *mut Void) -> Boolean;

    fn HidP_GetCaps(PHIDP_PREPARSED_DATA: *mut Void, Capabilities: *mut Void) -> NTStatus;

    fn _HidD_GetInputReport(HidDeviceObject: *const Void, ReportBuffer: *mut Void, ReportBufferLength: u32) -> Boolean;

    fn HidP_GetData(ReportType: u32, DataList: *mut Void, DataLength: *const u32, PHIDP_PREPARSED_DATA: *mut Void, Report: *mut Void, ReportLength: u32) -> NTStatus;

    fn HidP_MaxDataListLength(ReportType: u32, PHIDP_PREPARSED_DATA: *mut Void) -> ULong;

    fn HidD_FlushQueue(HidDeviceObject: *const Void) -> Boolean;
}

#[macro_export]
macro_rules! Check {
    ($msg:expr) => {
        let err = unsafe { GetLastError() };
        if err != 0
        {
            println!("Error {}, at {}",err, $msg);
        }
    };
}
