use std::mem::ManuallyDrop;
use std::ptr;

use windows::core::{implement, w, Interface, Ref, BSTR, HRESULT, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, E_FAIL, HANDLE};
use windows::Win32::System::Com::*;
use windows::Win32::System::Ole::*;
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Threading::SetEvent;
use windows::Win32::System::Variant::*;
use windows::Win32::System::Wmi::*;

use crate::log;
use crate::protocol::*;

const SIGN: [u8; 4] = [0x53, 0x45, 0x43, 0x55]; // "SECU"

pub struct WmiConnection {
    services: IWbemServices,
    obj_path: BSTR,
}

impl WmiConnection {
    /// Initialize COM and connect to root\wmi. Call once from the service thread.
    pub fn connect() -> Result<Self, u8> {
        // SAFETY: connect_inner initializes COM on this thread and connects to
        // WMI. Must be called once per thread; caller (service_main) ensures this.
        unsafe { Self::connect_inner().map_err(|_| STATUS_WMI_ERROR) }
    }

    unsafe fn connect_inner() -> windows::core::Result<Self> {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;

        CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )?;

        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;

        let services = locator.ConnectServer(
            &BSTR::from("root\\wmi"),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        )?;

        CoSetProxyBlanket(
            &services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )?;

        // Find the singleton hpqBIntM instance path
        let enumerator = services.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from("SELECT * FROM hpqBIntM"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )?;

        let mut objs = [None; 1];
        let mut returned = 0u32;
        enumerator
            .Next(WBEM_INFINITE, &mut objs, &mut returned)
            .ok()?;
        let inst = objs[0].take().ok_or(windows::core::Error::from(E_FAIL))?;

        let obj_path = get_bstr(&inst, w!("__RELPATH"))?;

        Ok(Self { services, obj_path })
    }

    pub fn read_thermal(&self) -> Result<u8, u8> {
        // SAFETY: bios_call requires valid COM state; guaranteed by connect() success.
        // Parameters match the hpqBIOSInt4 contract (Command=1=read, CT=76).
        let (rc, data) = unsafe { self.bios_call(1, 76, &[0, 0, 0, 0])? };
        if rc != 0 {
            return Err(STATUS_WMI_ERROR);
        }
        Ok(data[0])
    }

    pub fn set_thermal(&self, mode: u8) -> Result<(), u8> {
        // SAFETY: Same COM contract as read_thermal; Command=2=write, CT=76.
        let (rc, _) = unsafe { self.bios_call(2, 76, &[mode, 0, 0, 0])? };
        if rc != 0 {
            return Err(STATUS_WMI_ERROR);
        }
        Ok(())
    }

    pub fn read_coolsense(&self) -> Result<u8, u8> {
        // SAFETY: Same COM contract as read_thermal; Command=1=read, CT=44.
        let (rc, data) = unsafe { self.bios_call(1, 44, &[0, 0, 0, 0])? };
        if rc != 0 {
            return Err(STATUS_WMI_ERROR);
        }
        Ok(data[1]) // Data[1] = CoolSense state (0=off, 1=on)
    }

    /// Read CPU package temperature in Celsius.
    /// Primary: Intel ESIF instance _3 (Package Domain) — accurate, responsive.
    /// Fallback: ACPI MSAcpi_ThermalZoneTemperature max (broken on Hayden —
    /// TZ00 stuck at 28°C, TZ02 reads 10°C).
    pub fn read_temp(&self) -> Result<u8, u8> {
        // SAFETY: COM is initialized and `self.services` is a valid IWbemServices.
        unsafe {
            if let Ok(t) = self.read_esif_temp() {
                return Ok(t);
            }
            self.read_acpi_temp()
        }
    }

    /// Read CPU package temp from Intel ESIF (DPTF/IPF framework).
    /// Queries EsifDeviceInformation in root\wmi — same namespace we're
    /// already connected to. Instance _3 = Package Domain (confirmed in
    /// experiment 12: tracks 56°C idle → 73°C under 20-thread stress).
    unsafe fn read_esif_temp(&self) -> Result<u8, u8> {
        let enumerator = self
            .services
            .ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from("SELECT Temperature, InstanceName FROM EsifDeviceInformation"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
            .map_err(|_| STATUS_WMI_ERROR)?;

        loop {
            let mut objs = [None; 1];
            let mut returned = 0u32;
            let hr = enumerator.Next(WBEM_INFINITE, &mut objs, &mut returned);
            if hr.is_err() || returned == 0 {
                break;
            }
            let Some(obj) = objs[0].take() else { break };

            // Instance name format: "..._N" where N is the participant index.
            // We want _3 (Package Domain).
            let Ok(name) = get_bstr(&obj, w!("InstanceName")) else {
                continue;
            };
            if !name.to_string().ends_with("_3") {
                continue;
            }
            if let Ok(temp) = get_u32(&obj, w!("Temperature")) {
                let t = temp.clamp(0, 255) as u8;
                if t > 0 {
                    return Ok(t);
                }
            }
        }
        Err(STATUS_WMI_ERROR)
    }

    /// Fallback: ACPI thermal zones (max across all zones).
    unsafe fn read_acpi_temp(&self) -> Result<u8, u8> {
        let enumerator = self
            .services
            .ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from("SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
            .map_err(|_| STATUS_WMI_ERROR)?;

        let mut max_c: i32 = 0;
        loop {
            let mut objs = [None; 1];
            let mut returned = 0u32;
            let hr = enumerator.Next(WBEM_INFINITE, &mut objs, &mut returned);
            if hr.is_err() || returned == 0 {
                break;
            }
            let Some(obj) = objs[0].take() else { break };
            if let Ok(raw) = get_u32(&obj, w!("CurrentTemperature")) {
                // Value is in tenths of Kelvin
                let c = (raw as i32 - 2732) / 10;
                if c > max_c {
                    max_c = c;
                }
            }
        }
        Ok(max_c.clamp(0, 255) as u8)
    }

    /// Subscribe to hpqBEvnt via a push-based async sink. Returns a live
    /// subscription that signals `fn_key` (the auto-reset event the tray waits
    /// on) whenever Fn+F12 (EventId 29) is pressed. Zero idle cost: WMI invokes
    /// the sink only when an event actually fires — no polling thread. Takes
    /// ownership of `fn_key` (released when the subscription is dropped).
    ///
    /// The sink is wrapped in an unsecured-apartment stub so that only WMI's
    /// SYSTEM context can invoke the callback — closing the documented async-sink
    /// security hole (raw async callbacks are otherwise the least-secure WMI mode).
    pub fn subscribe_events(&self, fn_key: HANDLE) -> Result<EventSubscription, u8> {
        // SAFETY: COM MTA is initialized on this thread (connect() ran here); all
        // interfaces below are valid for the duration of the calls.
        unsafe {
            let sink: IWbemObjectSink = FnKeySink {
                fn_key: fn_key.0 as isize,
            }
            .into();

            // Secure the callback: the stub can only be invoked by WMI (SYSTEM),
            // not by arbitrary local processes.
            let apartment: IUnsecuredApartment =
                CoCreateInstance(&UnsecuredApartment, None, CLSCTX_LOCAL_SERVER).map_err(|e| {
                    log::write(&format!("CoCreateInstance(UnsecuredApartment) failed: {e}"));
                    STATUS_WMI_ERROR
                })?;
            let stub_unk = apartment.CreateObjectStub(&sink).map_err(|e| {
                log::write(&format!("CreateObjectStub failed: {e}"));
                STATUS_WMI_ERROR
            })?;
            let stub: IWbemObjectSink = stub_unk.cast().map_err(|_| STATUS_WMI_ERROR)?;

            self.services
                .ExecNotificationQueryAsync(
                    &BSTR::from("WQL"),
                    &BSTR::from("SELECT * FROM hpqBEvnt"),
                    WBEM_GENERIC_FLAG_TYPE(0),
                    None,
                    &stub,
                )
                .map_err(|e| {
                    log::write(&format!("ExecNotificationQueryAsync(hpqBEvnt) failed: {e}"));
                    STATUS_WMI_ERROR
                })?;

            log::write("event listener: hpqBEvnt async sink registered");
            Ok(EventSubscription {
                services: self.services.clone(),
                stub,
                fn_key,
                _apartment: apartment,
                _sink: sink,
            })
        }
    }

    /// Read current display brightness (0-100).
    /// Uses WmiMonitorBrightness in root\wmi (Intel driver PWM control).
    pub fn read_brightness(&self) -> Result<u8, u8> {
        // SAFETY: COM is initialized and self.services is a valid IWbemServices.
        unsafe {
            let enumerator = self
                .services
                .ExecQuery(
                    &BSTR::from("WQL"),
                    &BSTR::from("SELECT CurrentBrightness FROM WmiMonitorBrightness"),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    None,
                )
                .map_err(|_| STATUS_WMI_ERROR)?;

            let mut objs = [None; 1];
            let mut returned = 0u32;
            let _ = enumerator.Next(WBEM_INFINITE, &mut objs, &mut returned);
            if returned == 0 {
                return Err(STATUS_WMI_ERROR);
            }
            let obj = objs[0].take().ok_or(STATUS_WMI_ERROR)?;
            let val = get_u32(&obj, w!("CurrentBrightness"))?;
            Ok(val.clamp(0, 100) as u8)
        }
    }

    /// Set display brightness (0-100) via WmiMonitorBrightnessMethods.WmiSetBrightness.
    /// Timeout=0 = apply immediately. Intel driver controls PWM directly --
    /// no power state transition, no Modern Standby trigger.
    pub fn set_brightness(&self, level: u8) -> Result<(), u8> {
        // SAFETY: COM is initialized. ExecQuery finds the instance path,
        // GetObject+GetMethod builds the input params, ExecMethod invokes.
        unsafe {
            let enumerator = self
                .services
                .ExecQuery(
                    &BSTR::from("WQL"),
                    &BSTR::from("SELECT * FROM WmiMonitorBrightnessMethods"),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    None,
                )
                .map_err(|_| STATUS_WMI_ERROR)?;

            let mut objs = [None; 1];
            let mut returned = 0u32;
            let _ = enumerator.Next(WBEM_INFINITE, &mut objs, &mut returned);
            if returned == 0 {
                return Err(STATUS_WMI_ERROR);
            }
            let inst = objs[0].take().ok_or(STATUS_WMI_ERROR)?;
            let inst_path = get_bstr(&inst, w!("__RELPATH")).map_err(|_| STATUS_WMI_ERROR)?;

            let mut class_def = None;
            self.services
                .GetObject(
                    &BSTR::from("WmiMonitorBrightnessMethods"),
                    Default::default(),
                    None,
                    Some(&mut class_def),
                    None,
                )
                .map_err(|_| STATUS_WMI_ERROR)?;

            let mut in_sig = None;
            class_def
                .ok_or(STATUS_WMI_ERROR)?
                .GetMethod(w!("WmiSetBrightness"), 0, &mut in_sig, ptr::null_mut())
                .map_err(|_| STATUS_WMI_ERROR)?;

            let in_params = in_sig
                .ok_or(STATUS_WMI_ERROR)?
                .SpawnInstance(0)
                .map_err(|_| STATUS_WMI_ERROR)?;

            let var_timeout = var_from_u32(0);
            in_params
                .Put(w!("Timeout"), 0, &var_timeout, 0)
                .map_err(|_| STATUS_WMI_ERROR)?;
            let var_level = var_from_u32(level as u32);
            in_params
                .Put(w!("Brightness"), 0, &var_level, 0)
                .map_err(|_| STATUS_WMI_ERROR)?;

            self.services
                .ExecMethod(
                    &inst_path,
                    &BSTR::from("WmiSetBrightness"),
                    Default::default(),
                    None,
                    &in_params,
                    None,
                    None,
                )
                .map_err(|_| STATUS_WMI_ERROR)?;

            Ok(())
        }
    }

    pub fn set_coolsense(&self, on: u8) -> Result<(), u8> {
        // Must read first to preserve the flags byte (Data[0])
        // SAFETY: Same COM contract as read_coolsense; read before write to preserve flags.
        let (rc, current) = unsafe { self.bios_call(1, 44, &[0, 0, 0, 0])? };
        if rc != 0 {
            return Err(STATUS_WMI_ERROR);
        }
        // SAFETY: Same COM contract; Command=2=write, CT=44, preserving flags byte.
        let (rc, _) = unsafe { self.bios_call(2, 44, &[current[0], on, 0, 0])? };
        if rc != 0 {
            return Err(STATUS_WMI_ERROR);
        }
        Ok(())
    }

    /// Execute an `hpqBIOSInt4` call (4-byte data). Thin wrapper over
    /// `bios_call_method`; returns (rwReturnCode, Data[0..4]).
    unsafe fn bios_call(
        &self,
        command: u32,
        command_type: u32,
        data: &[u8; 4],
    ) -> Result<(u32, [u8; 4]), u8> {
        let (rc, bytes) = self.bios_call_method("hpqBIOSInt4", command, command_type, data)?;
        let mut result = [0u8; 4];
        let len = bytes.len().min(4);
        result[..len].copy_from_slice(&bytes[..len]);
        Ok((rc, result))
    }

    /// Execute a BIOS WMI call via the named method: `hpqBIOSInt4` (4-byte data)
    /// or `hpqBIOSInt128` (128-byte data). Returns (rwReturnCode, OutData.Data).
    /// The output length is provider-determined by the method name — do NOT pad
    /// the 4-byte input (padding to 128 yields "Invalid parameter"; the CT13
    /// capability read uses `hpqBIOSInt128` with Command=1 and 4 input bytes).
    /// Error codes 0x10-0x2F pinpoint the failing step for debug.
    unsafe fn bios_call_method(
        &self,
        method: &str,
        command: u32,
        command_type: u32,
        data: &[u8; 4],
    ) -> Result<(u32, Vec<u8>), u8> {
        let method_w: Vec<u16> = method.encode_utf16().chain(std::iter::once(0)).collect();

        // Step 0x10: Get hpqBDataIn class
        let mut in_data_class = None;
        self.services
            .GetObject(
                &BSTR::from("hpqBDataIn"),
                Default::default(),
                None,
                Some(&mut in_data_class),
                None,
            )
            .map_err(|e| {
                log::write(&format!("GetObject(hpqBDataIn) failed: {e}"));
                0x10u8
            })?;
        let in_data_class_obj = in_data_class.ok_or(0x11u8)?;

        let in_data = in_data_class_obj.SpawnInstance(0).map_err(|e| {
            log::write(&format!("SpawnInstance(hpqBDataIn) failed: {e}"));
            0x12u8
        })?;

        // Step 0x13-0x17: Set properties on hpqBDataIn instance
        log_put_u32(&in_data, "Command", w!("Command"), command, 0x13u8)?;
        log_put_u32(
            &in_data,
            "CommandType",
            w!("CommandType"),
            command_type,
            0x14u8,
        )?;
        log_put_u32(
            &in_data,
            "Size",
            w!("Size"),
            if command == 2 { 4 } else { 0 },
            0x15u8,
        )?;
        put_bytes(&in_data, w!("hpqBData"), data).map_err(|_| 0x16u8)?;
        put_bytes(&in_data, w!("Sign"), &SIGN).map_err(|_| 0x17u8)?;

        // Step 0x18: Get hpqBIntM class definition
        let mut class_def = None;
        self.services
            .GetObject(
                &BSTR::from("hpqBIntM"),
                Default::default(),
                None,
                Some(&mut class_def),
                None,
            )
            .map_err(|_| 0x18u8)?;

        // Step 0x19-0x1B: Get method signature and create input params
        let mut in_sig = None;
        class_def
            .ok_or(0x19u8)?
            .GetMethod(PCWSTR(method_w.as_ptr()), 0, &mut in_sig, ptr::null_mut())
            .map_err(|_| 0x1Au8)?;

        let in_params = in_sig.ok_or(0x1Bu8)?.SpawnInstance(0).map_err(|_| 0x1Cu8)?;

        // Step 0x1D: Set InData = our hpqBDataIn instance (embedded object)
        put_object(&in_params, w!("InData"), &in_data).map_err(|_| 0x1Du8)?;

        // Step 0x1E: Execute the method
        let mut out_params = None;
        self.services
            .ExecMethod(
                &self.obj_path,
                &BSTR::from(method),
                Default::default(),
                None,
                &in_params,
                Some(&mut out_params),
                None,
            )
            .map_err(|_| 0x1Eu8)?;

        let out = out_params.ok_or(0x1Fu8)?;

        // Step 0x20-0x22: Extract OutData
        let out_data = get_object(&out, w!("OutData")).map_err(|_| 0x20u8)?;
        let rc = get_u32(&out_data, w!("rwReturnCode")).map_err(|_| 0x21u8)?;
        let bytes = get_bytes(&out_data, w!("Data")).map_err(|_| 0x22u8)?;

        Ok((rc, bytes))
    }
}

// ---------------------------------------------------------------------------
// hpqBEvnt async event sink (push-based, zero idle cost)
// ---------------------------------------------------------------------------

/// Pure predicate: which hpqBEvnt `EventId` triggers the Fn+F12 screen toggle.
/// Extracted from the COM callback so it can be unit-tested without WMI. Only
/// EventId 29 (the "three-diamonds" Fn+F12 key) signals; every other event
/// (26 = camera shutter, 3 = periodic, ...) is ignored.
pub(crate) fn should_signal_fn_key(event_id: u32) -> bool {
    event_id == 29
}

/// COM sink that WMI calls (on its own threadpool thread) whenever an hpqBEvnt
/// event fires. Holds only a raw auto-reset event handle — `SetEvent` is
/// kernel-synchronized and safe to call from any thread. `Indicate` does O(1)
/// work with zero allocation, so an event flood coalesces into repeated
/// `SetEvent`s (each a no-op once signaled) and cannot grow memory or a queue.
#[implement(IWbemObjectSink)]
struct FnKeySink {
    fn_key: isize,
}

impl IWbemObjectSink_Impl for FnKeySink_Impl {
    fn Indicate(
        &self,
        count: i32,
        objs: *const Option<IWbemClassObject>,
    ) -> windows::core::Result<()> {
        if count <= 0 || objs.is_null() {
            return Ok(());
        }
        // SAFETY: WMI guarantees `objs` points to `count` valid entries for the
        // duration of this call; we only read them.
        let batch = unsafe { std::slice::from_raw_parts(objs, count as usize) };
        for obj in batch.iter().flatten() {
            // SAFETY: `obj` is a valid IWbemClassObject supplied by WMI.
            let Ok(id) = (unsafe { get_u32(obj, w!("EventId")) }) else {
                continue;
            };
            if log::is_verbose() {
                // SAFETY: same valid object.
                let data = unsafe { get_u32(obj, w!("EventData")) }.unwrap_or(0);
                log::write(&format!("hpqBEvnt: id={id} data=0x{data:04X}"));
            }
            if should_signal_fn_key(id) {
                let h = HANDLE(self.fn_key as *mut core::ffi::c_void);
                // SAFETY: `fn_key` is a valid auto-reset event owned by the
                // EventSubscription, alive until CancelAsyncCall returns.
                unsafe {
                    let _ = SetEvent(h);
                }
            }
        }
        Ok(())
    }

    fn SetStatus(
        &self,
        _flags: i32,
        _hr: HRESULT,
        _param: &BSTR,
        _obj: Ref<'_, IWbemClassObject>,
    ) -> windows::core::Result<()> {
        Ok(())
    }
}

/// Live hpqBEvnt async subscription. Lives on the service thread for the
/// service's lifetime; `Drop` deterministically cancels the async call (after
/// which no callback can run) and then releases the event handle — giving a
/// clean, race-free shutdown with a logged "cancelled" line.
pub struct EventSubscription {
    services: IWbemServices,
    stub: IWbemObjectSink,
    fn_key: HANDLE,
    // Kept alive for the subscription's lifetime; ordering of drop is irrelevant
    // because CancelAsyncCall (below) severs the callback path first.
    _apartment: IUnsecuredApartment,
    _sink: IWbemObjectSink,
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        // SAFETY: `services` and `stub` are valid; we pass the SAME stub we
        // registered. CancelAsyncCall guarantees no further Indicate callbacks
        // once it returns, so releasing `fn_key` afterward cannot race a signal.
        unsafe {
            let _ = self.services.CancelAsyncCall(&self.stub);
        }
        log::write("event listener: cancelled");
        // SAFETY: no callback can touch fn_key after the cancel above.
        unsafe {
            let _ = CloseHandle(self.fn_key);
        }
    }
}

// ---------------------------------------------------------------------------
// VARIANT helpers -- create
// ---------------------------------------------------------------------------

unsafe fn log_put_u32(
    obj: &IWbemClassObject,
    label: &str,
    name: PCWSTR,
    val: u32,
    step: u8,
) -> Result<(), u8> {
    let var = var_from_u32(val);
    obj.Put(name, 0, &var, 0).map_err(|e| {
        log::write(&format!("Put({label}, {val}) failed: {e}"));
        step
    })
}

unsafe fn put_bytes(obj: &IWbemClassObject, name: PCWSTR, data: &[u8]) -> Result<(), u8> {
    let mut var = var_from_bytes(data).map_err(|_| STATUS_WMI_ERROR)?;
    obj.Put(name, 0, &var, 0).map_err(|_| STATUS_WMI_ERROR)?;
    VariantClear(&mut var).map_err(|_| STATUS_WMI_ERROR)?;
    Ok(())
}

unsafe fn put_object(
    obj: &IWbemClassObject,
    name: PCWSTR,
    embedded: &IWbemClassObject,
) -> Result<(), u8> {
    let mut var = var_from_object(embedded).map_err(|_| STATUS_WMI_ERROR)?;
    obj.Put(name, 0, &var, 0).map_err(|_| STATUS_WMI_ERROR)?;
    VariantClear(&mut var).map_err(|_| STATUS_WMI_ERROR)?;
    Ok(())
}

unsafe fn var_from_u32(val: u32) -> VARIANT {
    let mut v = VARIANT::default();
    (*v.Anonymous.Anonymous).vt = VT_I4;
    (*v.Anonymous.Anonymous).Anonymous.lVal = val as i32;
    v
}

unsafe fn var_from_bytes(data: &[u8]) -> windows::core::Result<VARIANT> {
    let psa = SafeArrayCreateVector(VT_UI1, 0, data.len() as u32);
    if psa.is_null() {
        return Err(E_FAIL.into());
    }
    let mut raw: *mut std::ffi::c_void = ptr::null_mut();
    SafeArrayAccessData(psa, &mut raw)?;
    ptr::copy_nonoverlapping(data.as_ptr(), raw as *mut u8, data.len());
    SafeArrayUnaccessData(psa)?;

    let mut v = VARIANT::default();
    (*v.Anonymous.Anonymous).vt = VARENUM(VT_ARRAY.0 | VT_UI1.0);
    (*v.Anonymous.Anonymous).Anonymous.parray = psa;
    Ok(v)
}

unsafe fn var_from_object(obj: &IWbemClassObject) -> windows::core::Result<VARIANT> {
    let unknown: windows::core::IUnknown = obj.cast()?;
    let mut v = VARIANT::default();
    (*v.Anonymous.Anonymous).vt = VT_UNKNOWN;
    (*v.Anonymous.Anonymous).Anonymous.punkVal = ManuallyDrop::new(Some(unknown));
    Ok(v)
}

// ---------------------------------------------------------------------------
// VARIANT helpers — read
// ---------------------------------------------------------------------------

unsafe fn get_u32(obj: &IWbemClassObject, name: PCWSTR) -> Result<u32, u8> {
    let mut var = VARIANT::default();
    obj.Get(name, 0, &mut var, None, None)
        .map_err(|_| STATUS_WMI_ERROR)?;
    let inner = &*var.Anonymous.Anonymous;
    match VARENUM(inner.vt.0) {
        VT_UI4 => Ok(inner.Anonymous.ulVal),
        VT_I4 => Ok(inner.Anonymous.lVal as u32),
        _ => Err(STATUS_WMI_ERROR),
    }
}

unsafe fn get_bytes(obj: &IWbemClassObject, name: PCWSTR) -> Result<Vec<u8>, u8> {
    let mut var = VARIANT::default();
    obj.Get(name, 0, &mut var, None, None)
        .map_err(|_| STATUS_WMI_ERROR)?;
    let psa = (*var.Anonymous.Anonymous).Anonymous.parray;
    if psa.is_null() {
        return Err(STATUS_WMI_ERROR);
    }
    let lower = SafeArrayGetLBound(psa, 1).map_err(|_| STATUS_WMI_ERROR)?;
    let upper = SafeArrayGetUBound(psa, 1).map_err(|_| STATUS_WMI_ERROR)?;
    let len = (upper - lower + 1) as usize;
    let mut raw: *mut std::ffi::c_void = ptr::null_mut();
    SafeArrayAccessData(psa, &mut raw).map_err(|_| STATUS_WMI_ERROR)?;
    let bytes = std::slice::from_raw_parts(raw as *const u8, len).to_vec();
    SafeArrayUnaccessData(psa).map_err(|_| STATUS_WMI_ERROR)?;
    Ok(bytes)
}

unsafe fn get_object(obj: &IWbemClassObject, name: PCWSTR) -> Result<IWbemClassObject, u8> {
    let mut var = VARIANT::default();
    obj.Get(name, 0, &mut var, None, None)
        .map_err(|_| STATUS_WMI_ERROR)?;
    let inner = &*var.Anonymous.Anonymous;
    let punk: &ManuallyDrop<Option<windows::core::IUnknown>> = &inner.Anonymous.punkVal;
    let unknown = punk.as_ref().ok_or(STATUS_WMI_ERROR)?.clone();
    unknown.cast().map_err(|_| STATUS_WMI_ERROR)
}

unsafe fn get_bstr(obj: &IWbemClassObject, name: PCWSTR) -> windows::core::Result<BSTR> {
    let mut var = VARIANT::default();
    obj.Get(name, 0, &mut var, None, None)?;
    let inner = &*var.Anonymous.Anonymous;
    let bstr: &ManuallyDrop<BSTR> = &inner.Anonymous.bstrVal;
    Ok((**bstr).clone())
}

// ---------------------------------------------------------------------------
// Async-sink safety tests (no WMI/hardware required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::WAIT_OBJECT_0;
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    /// Only EventId 29 (Fn+F12) drives the screen toggle — the whole decision the
    /// COM callback makes, isolated so it is testable without WMI and Miri-clean.
    #[test]
    fn only_event_29_signals_fn_key() {
        assert!(should_signal_fn_key(29));
        for id in [0u32, 3, 26, 28, 30, 100, u32::MAX] {
            assert!(!should_signal_fn_key(id), "id {id} must not signal");
        }
    }

    /// An empty batch must be a no-op: the sink must not dereference the array
    /// or the handle. (The `#[implement]` trait method WMI calls directly also
    /// guards `count <= 0` and null pointers; the safe wrapper can only produce
    /// count 0 here, which is the case that matters for the flood/idle path.)
    #[test]
    fn indicate_tolerates_empty_batch() {
        let sink: IWbemObjectSink = FnKeySink { fn_key: 0 }.into();
        // SAFETY: empty slice -> count 0 -> Indicate early-returns, touching nothing.
        unsafe {
            sink.Indicate(&[]).unwrap();
        }
    }

    /// The signal primitive the sink uses: repeated `SetEvent` on an auto-reset
    /// event coalesces to a single wake — this is why an event flood is bounded
    /// (no queue growth) and cannot be used to spin the tray.
    #[test]
    fn set_event_on_auto_reset_coalesces_to_one_wake() {
        // SAFETY: standard Win32 auto-reset event; all handles checked/closed.
        unsafe {
            let ev = CreateEventW(None, false, false, PCWSTR::null()).unwrap();
            for _ in 0..1000 {
                let _ = SetEvent(ev);
            }
            // One wake is available...
            assert_eq!(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
            // ...and it auto-reset, so the next immediate wait times out.
            assert_ne!(WaitForSingleObject(ev, 0), WAIT_OBJECT_0);
            let _ = CloseHandle(ev);
        }
    }
}
