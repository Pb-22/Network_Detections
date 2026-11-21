# OT-MODBUS-007: parsed register-write rejection, reason 04.
@load base/protocols/modbus
@load base/frameworks/notice

module ModbusWriteRejection;

export {
    redef enum Notice::Type += {
        ## A responder rejected FC06 or FC16 with Server Device Failure (04).
        Register_Write_Server_Device_Failure
    };
}

# The pinned native parser dispatches ModbusTCP_ExceptResponse only on
# the responder branch. HeaderToVal preserves the raw exception FC.
# Each parsed ADU raises its own event after TCP stream reassembly.
event modbus_exception(c: connection, headers: ModbusHeaders, code: count)
    {
    if ( headers$pid == 0 && headers$len == 3 && code == 4 &&
         (headers$function_code == 0x86 || headers$function_code == 0x90) )
        {
        NOTICE([$note=Register_Write_Server_Device_Failure,
                $conn=c,
                $msg=fmt("Modbus responder rejected register write FC%02d with Server Device Failure (04)",
                         headers$function_code - 0x80),
                $sub=fmt("transaction_id=%d unit_id=%d function_code=%d exception_code=%d protocol_id=%d mbap_length=%d",
                         headers$tid, headers$uid, headers$function_code - 0x80,
                         code, headers$pid, headers$len),
                $actions=set(Notice::ACTION_LOG),
                $suppress_for=0secs]);
        }
    }
