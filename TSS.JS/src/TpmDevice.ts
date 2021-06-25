/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */


export class TpmError extends Error
{
    constructor(
        public responseCode: number,
        public tpmCommand: string,
        errorMessage: string = null)
    {
        super(errorMessage);
    }
}


export enum TSS_TPM_INFO {
    // Flags corresponding to the TpmEndPointInfo values used by the TPM simulator
    TSS_TpmPlatformAvailable = 0x01,
    TSS_TpmUsesTbs = 0x02,
    TSS_TpmInRawMode = 0x04,
    TSS_TpmSupportsPP = 0x08,

    // TPM connection type. Flags are mutually exclusive for better error checking
    TSS_SocketConn = 0x1000,
    TSS_TbsConn = 0x2000
};


/**
 * Interface to be implemented by classes representing various flavors of a TPM device
 */
export interface TpmDevice
{
    /**
     * Returns an error object if connection attempt fails before asyncronous phase commences
     */
    connect(continuation: (err: TpmError) => void): Error;

    /**
     * Sends the command buffe in the TPM wire format to the TPM device,
     * and returns the TPM response buffer via the callback.
     */
    dispatchCommand(command: Buffer, continuation: (err: TpmError, response?: Buffer) => void): void;

    /**
     * Closes the connection with the TPM device and releases associated system resources
     */
    close(): void;
}


export class TpmLinuxDevice implements TpmDevice
{
    private static readonly InvalidHandle: number = -1;
    private static fs = null;

    public constructor(
        private devTpmHandle: number = TpmLinuxDevice.InvalidHandle
    ) {}

    public connect(continuation: (err: TpmError) => void): Error
    {
        if (this.devTpmHandle == TpmLinuxDevice.InvalidHandle)
        {
            if (TpmLinuxDevice.fs == null)
                TpmLinuxDevice.fs = require('fs');

            try {
                this.devTpmHandle = TpmLinuxDevice.fs.openSync('/dev/tpm0', 'rs+');
                //console.log("Connected to the raw TPM device\r\n");
            }
            catch (eTrm) {
                try {
                    this.devTpmHandle = TpmLinuxDevice.fs.openSync('/dev/tpmrm0', 'rs+');
                    //console.log("Connected to the TPM RM device\r\n");
                }
                catch (eTpm) {
                    //console.log("Failed to connect to both raw TPM and TPM RM devices\r\n");
                    return eTpm;
                }
            }
        }
        setImmediate(continuation, null);
        return null;
    }

    public dispatchCommand(command: Buffer, continuation: (err: TpmError, resp?: Buffer) => void): void
    {
        let err: TpmError = null;
        let respBuf: Buffer = null;
        let numWritten: number = TpmLinuxDevice.fs.writeSync(this.devTpmHandle, command, 0, command.length);
        if (numWritten != command.length)
        {
            let errMsg = 'Only ' + numWritten + ' bytes written to the TPM device instead of ' + command.length;
            console.log(errMsg);
            err = new TpmError(TPM_RC.TSS_SEND_OP_FAILED, 'TpmSend', errMsg);
        }
        else
        {
            respBuf = new Buffer(4096);
            let numRead: number = TpmLinuxDevice.fs.readSync(this.devTpmHandle, respBuf, 0, respBuf.length, null);
            respBuf = respBuf.slice(0, numRead);
        }
        setImmediate(continuation, err, respBuf);
    }

    public close(): void
    {
        if (this.devTpmHandle != TpmLinuxDevice.InvalidHandle)
        {
            TpmLinuxDevice.fs.closeSync(this.devTpmHandle);
            this.devTpmHandle = TpmLinuxDevice.InvalidHandle;
        }
    }
}; // class TpmLinuxDevice

export class TpmTbsDevice implements TpmDevice
{
    private static ffi = null;
    private static ref = null;
    private static Struct = null;
    private static ArrayType = null;
    private static ByteArray = null;
    private static byte = null;
    private static int = null;
    private static TbsContext = null;

    //let PTbsContext = ref.refType(TbsContext);

    public constructor(
        private tbsHandle: number = 0,
        private tbsDll = null
    ) {
        if (TpmTbsDevice.ffi == null)
        {
            TpmTbsDevice.ffi = require('ffi-napi');
            TpmTbsDevice.ref = require('ref-napi');
            TpmTbsDevice.Struct = require('ref-struct-di')(TpmTbsDevice.ref);;
            TpmTbsDevice.ArrayType = require('ref-array-di')(TpmTbsDevice.ref);

            TpmTbsDevice.byte = TpmTbsDevice.ref.types.byte;
            TpmTbsDevice.ByteArray = TpmTbsDevice.ArrayType(TpmTbsDevice.byte);
            TpmTbsDevice.int = TpmTbsDevice.ref.types.int;

            TpmTbsDevice.TbsContext = TpmTbsDevice.Struct({
                                            version: TpmTbsDevice.ref.types.int,
                                            params: TpmTbsDevice.ref.types.int
                                    });
        }
    }

    public connect(continuation: (err: TpmError) => void): Error
    {
        this.tbsDll = TpmTbsDevice.ffi.Library('Tbs', {
                'Tbsi_Context_Create': ['int', ['pointer', 'pointer']],
                'Tbsip_Context_Close': ['int', ['int']],
                'Tbsip_Submit_Command': ['int', ['int' /*handle*/, 'int' /*locality*/, 'int' /*priority*/,
                    TpmTbsDevice.ByteArray /*inBuf*/, 'int' /*inBufLen*/,
                    TpmTbsDevice.ByteArray /*outBuf*/, 'pointer' /*outBufLen*/]]
            });

        let tbsCtx = new TpmTbsDevice.TbsContext();
        tbsCtx.version = 2;
        tbsCtx.params = 1 << 2;
        //var tbsHandle = ref.NULL;
        var handleOut = TpmTbsDevice.ref.alloc('long', 0);

        let err: TpmError = null;
        let res = this.tbsDll.Tbsi_Context_Create(tbsCtx.ref(), handleOut);
        if (res == 0)
            this.tbsHandle = handleOut.deref();
        else
            err = new TpmError(res, 'Tbsi_Context_Create', 'TBS context cretaion failed');

        setImmediate(continuation, err);
        return null;
    }

    public dispatchCommand(command: Buffer, continuation: (err: TpmError, resp?: Buffer) => void): void
    {
        let respBuf = new TpmTbsDevice.ByteArray(4096);
        let respSizePtr = TpmTbsDevice.ref.alloc('int', respBuf.length);
        let cmd = new TpmTbsDevice.ByteArray(command);

        let err: TpmError = null;
        let resp: Buffer = null;
        let res = this.tbsDll.Tbsip_Submit_Command(this.tbsHandle, 0, 0, cmd, command.length, respBuf, respSizePtr);

        if (res == 0)
            resp = new Buffer(respBuf.toArray().slice(0, respSizePtr.deref()));
        else
            err = new TpmError(res, 'Tbsip_Submit_Command', 'Sending TPM command to TBS failed');

        setImmediate(continuation, err, resp);
    }

    public close(): void
    {
        if (this.tbsHandle != 0)
            this.tbsDll.Tbsip_Context_Close(this.tbsHandle);
    }
}; // class TpmTbsDevice


import * as Net from 'net';
//import * as TPM from "./TpmTypes.js";
import { TPM_RC } from "./TpmTypes.js";
import { TpmBuffer } from "./TpmMarshaller.js";

const ClientVer : number = 1; 


enum TPM_TCP_PROTOCOL {
    SignalPowerOn = 1,
    //SignalPowerOff = 2,
    SendCommand = 8,
    SignalNvOn = 11,
    //SignalNvOff = 12,
    HandShake = 15,
    SessionEnd = 20,
    Stop = 21,
};

export class TpmTcpDevice implements TpmDevice
{
    public tpmInfo: TSS_TPM_INFO = null;

    public constructor(host: string = '127.0.0.1', port: number = 2321, linuxTrm: boolean = false)
    {
        this.host = host;
        this.port = port;
        this.linuxTrm = linuxTrm;
        this.oldTrm = true;
    }

    public connect(continuation: (err: TpmError) => void): Error
    {
        this.connectCont = continuation;
        this.tpmSocket = new Net.Socket();
        this.tpmSocket.connect(this.port, this.host, this.onConnect.bind(this));
        return null;
    }

    public dispatchCommand(command: Buffer, continuation: (err: TpmError, resp?: Buffer) => void): void
    {
        let extProt: boolean = this.linuxTrm && this.oldTrm;
        let cmdBuf = new TpmBuffer(command.length + 9 + (extProt ? 2 : 0));
        cmdBuf.writeInt(TPM_TCP_PROTOCOL.SendCommand);
        cmdBuf.writeByte(0);   // locality
        if (extProt)
        {
            cmdBuf.writeByte(0);   // debugMsgLevel
            cmdBuf.writeByte(1);   // commandSent status bit
        }
        cmdBuf.writeInt(command.length);
        command.copy(cmdBuf.buffer, cmdBuf.curPos);

        this.dispatchCont = continuation;
        this.tcpResp = new Buffer(0);
        this.tpmSocket.removeAllListeners('data');
        this.tpmSocket.on('data', this.onDispatch.bind(this));
        this.tpmSocket.write(cmdBuf.buffer);
    }

    public close(): void
    {
        if (this.tpmSocket != null) {
            this.tpmSocket.end();
            this.tpmSocket.unref();
            this.tpmSocket = null;
        }
        if (this.tpmPlatSocket != null) {
            this.tpmPlatSocket.end();
            this.tpmPlatSocket.unref();
            this.tpmPlatSocket = null;
        }
    }

    //
    // Private members
    //

    private tpmSocket: Net.Socket;

    // Scratch members
    private host: string;
    private port: number;
	protected linuxTrm: boolean;
	protected oldTrm: boolean;
    private tpmPlatSocket: Net.Socket;
    private tcpResp: Buffer;
    private connectCont: (err: TpmError) => void = null;
    private dispatchCont: (err: TpmError, resp?: Buffer) => void = null;

    private onConnect()
    {
        //console.log('Socket connection to the TPM endpoint established.\r\n');
        this.tcpResp = new Buffer(0);
        if (this.linuxTrm)
        {
            //console.log('Sending a protocol version discovery command...\r\n');
    	    let cmdGetRandom = [
		        0x80, 0x01,             // TPM_ST_NO_SESSIONS
		        0, 0, 0, 0x0C,          // length
		        0, 0, 0x01, 0x7B,       // TPM_CC_GetRandom
                0, 0x08                 // Command parameter - num random bytes to generate
            ];
            this.dispatchCommand(new Buffer(cmdGetRandom), this.onGetRandomCheck.bind(this));
        }
        else
        {
            this.tpmSocket.on('data', this.onHandShake.bind(this));
            let req = new Buffer([0, 0, 0, TPM_TCP_PROTOCOL.HandShake,
                                  0, 0, 0, ClientVer]);
            this.tpmSocket.write(req);
        }
    }

    private onGetRandomCheck(err: TpmError, resp: Buffer)
    {
        //console.log("onGetRandomCheck(" + err + ")\r\n");
        if (!err)
        {
            this.tpmSocket.removeAllListeners('data');
            if (resp.length != 20)
                err = new TpmError(TPM_RC.TSS_TCP_BAD_RESP_LEN, 'TrmConnect', 'Probe TPM2_GetRandom() failed');
        }
        if (err && this.oldTrm)
        {
            //console.log("Probing for an old TRM version failed: " + err);
            this.oldTrm = false;

            // Do not call onConnect directly from here, as the TRM has likely terminated the existin socket connection.
            this.close();
            this.connect(this.connectCont);
        }
        else
        {
            // Connection to the Linux user mode TRM completed
            setImmediate(this.connectCont, err);
        }
    }

    private onHandShake(lastRespFrag: Buffer)
    {
        this.tcpResp = Buffer.concat([this.tcpResp, lastRespFrag]);
        if (this.tcpResp.length < 12)
        {
            //console.log('Incomplete response received: ' + this.tcpResp.length + ' out of 12 bytes. Continue reading...');
            return;
        }

        this.tpmSocket.removeAllListeners('data');
        if (this.tcpResp.length != 12)
        {
            setImmediate(this.connectCont, new TpmError(TPM_RC.TSS_TCP_BAD_HANDSHAKE_RESP, 'SimConnect',
                            'Wrong length of the handshake response ' + this.tcpResp.length + ' bytes instead of 12'));
            return;
        }

        let simVer: number = this.tcpResp.readInt32BE(0);
        if (ClientVer != simVer)
        {
            setImmediate(this.connectCont, new TpmError(TPM_RC.TSS_TCP_SERVER_TOO_OLD, 'SimConnect',
                            'Too old TCP server version: ' + simVer));
            return;
        }

        this.tpmInfo = this.tcpResp.readInt32BE(4);
        //console.log('Simulator props: ' + this.tpmInfo);

        let ack: number = this.tcpResp.readInt32BE(8);
        if (ack != 0)
        {
            setImmediate(this.connectCont, new TpmError(TPM_RC.TSS_TCP_BAD_ACK, 'SimConnect',
                            'Bad ack for the handshake sequence'));
            return;
        }

        this.tpmInfo |= TSS_TPM_INFO.TSS_SocketConn;

        this.tpmPlatSocket = new Net.Socket();
        this.tpmPlatSocket.connect(this.port + 1, this.host, this.onPlatConnect.bind(this));
    }

    private onPlatConnect(resp: Buffer)
    {
        this.tpmPlatSocket.on('data', this.onPowerOnAck.bind(this));
        let req = new Buffer([0, 0, 0, TPM_TCP_PROTOCOL.SignalPowerOn]);
        this.tpmPlatSocket.write(req);
    }

    private onPowerOnAck(resp: Buffer)
    {
        this.tpmPlatSocket.removeAllListeners('data');

        if (resp.length != 4 || resp.readInt32BE(0) != 0)
        {
            setImmediate(this.connectCont, new TpmError(TPM_RC.TSS_TCP_BAD_ACK, 'SimPowerOn',
                         'Bad ack for the Simulator Power ON command'));
            return;
        }

        this.tpmPlatSocket.on('data', this.onNvOnAck.bind(this));
        let req = new Buffer([0, 0, 0, TPM_TCP_PROTOCOL.SignalNvOn]);
        this.tpmPlatSocket.write(req);
    }

    private onNvOnAck(resp: Buffer)
    {
        if (resp.length != 4 || resp.readInt32BE(0) != 0)
        {
            setImmediate(this.connectCont, new TpmError(TPM_RC.TSS_TCP_BAD_ACK, 'SimNvOn',
                         'Bad ack for the Simulator NV ON command'));
            return;
        }

        let req = new Buffer([0, 0, 0, TPM_TCP_PROTOCOL.SignalNvOn]);
//        this.tpmPlatSocket.end();
//        this.tpmPlatSocket.unref();
//        this.tpmPlatSocket = null;

        this.dispatchCommand(new Buffer([0x80,0x01,0x00,0x00,0x00,0x0C,0x00,0x00,0x01,0x44,0x00,0x00]),
                             this.onTpmStartup.bind(this));
    }

    private onTpmStartup(err: TpmError, resp: Buffer)
    {
        if (!err)
        {
            this.tpmSocket.removeAllListeners('data');

            if (resp.length == 10)
            {
                let rc: TPM_RC = resp.readInt32BE(6);
                if (rc != TPM_RC.SUCCESS && rc != TPM_RC.INITIALIZE)
                {
                    err = new TpmError(TPM_RC.TSS_TCP_UNEXPECTED_STARTUP_RESP, 'SimStartup',
                                         'Unexpected TPM2_Startup() response code ' + TPM_RC[rc]);
                }
            }
            else
                err = new TpmError(TPM_RC.TSS_TCP_BAD_RESP_LEN, 'SimStartup', 'Wrong length of TPM2_Startup response');
        }
        setImmediate(this.connectCont, err);
    }

    private onDispatch(lastRespFrag: Buffer)
    {
        this.tcpResp = Buffer.concat([this.tcpResp, lastRespFrag]);
        let respLen: number = this.tcpResp.readInt32BE(0);
        if (this.tcpResp.length < respLen + 8)
        {
            //console.log('Incomplete response received: ' + this.tcpResp.length + ' out of ' + (respLen + 8) + '. Continue reading...');
            return;
        }

        let err: TpmError = null;
        let resp: Buffer = null;
        if (respLen == this.tcpResp.length - 8)
        {
            let ack: number = this.tcpResp.readInt32BE(respLen + 4);
            if (ack == 0)
                resp = this.tcpResp.slice(4, respLen + 4);
            else
                err = new TpmError(TPM_RC.TSS_TCP_BAD_ACK, 'Dispatch', 'Bad ack during regular command dispatch');
        }
        else
        {
            err = new TpmError(TPM_RC.TSS_TCP_INVALID_SIZE_TAG, 'Dispatch', 'Invalid size tag in the TPM response TCP packet: '
                                    + respLen + ' instead of ' + this.tcpResp.length + ' bytes');
        }

        setImmediate(this.dispatchCont, err, resp);
    }
}; // class TpmTcpDevice
