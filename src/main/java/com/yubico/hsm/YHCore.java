package com.yubico.hsm;

import com.yubico.hsm.exceptions.YHAuthenticationException;
import com.yubico.hsm.exceptions.YHConnectionException;
import com.yubico.hsm.exceptions.YHDeviceException;
import com.yubico.hsm.exceptions.YHInvalidResponseException;
import com.yubico.hsm.internal.util.CommandUtils;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Command;
import com.yubico.hsm.yhconcepts.DeviceOption;
import com.yubico.hsm.yhconcepts.DeviceOptionValue;
import com.yubico.hsm.yhconcepts.YHError;
import com.yubico.hsm.yhdata.LogData;
import com.yubico.hsm.yhdata.LogEntry;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class YHCore {

    private static final int DEVICE_OPTION_VALUE_SIZE = 1;

    /**
     * Sends the Echo command with `data` as the input over an authenticated session
     *
     * @param session An authenticated session to communicate with the device over
     * @param data    The data that should be echoed back by the device
     * @return The device response to the Echo command. Should be the same as `data`
     * @throws YHConnectionException              If the connection to the device fails
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public static byte[] secureEcho(@NonNull final YHSession session, final byte[] data)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        return session.sendSecureCmd(Command.ECHO, data);
    }

    /**
     * Reset the device
     *
     * @param session An authenticated session to communicate with the device over
     * @throws YHConnectionException              If the connection to the device fails
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public static void resetDevice(@NonNull final YHSession session)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        log.info("Resetting the YubiHSM");
        byte[] resp = session.sendSecureCmd(Command.RESET_DEVICE, new byte[0]);
        CommandUtils.verifyResponseLength(Command.RESET_DEVICE, resp.length, 0);
    }

    /**
     * Get pseudo-random data of a specific length from the device
     *
     * @param session An authenticated session to communicate with the device over
     * @param length  The number of pseudo random bytes to return
     * @return `length` pseudo random bytes
     * @throws YHConnectionException              If the connection to the device fails
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public static byte[] getPseudoRandom(@NonNull final YHSession session, final int length)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        log.info("Getting " + length + " random bytes from the device");
        ByteBuffer data = ByteBuffer.allocate(2);
        data.putShort((short) length);
        byte[] resp = session.sendSecureCmd(Command.GET_PSEUDO_RANDOM, data.array());
        CommandUtils.verifyResponseLength(Command.GET_PSEUDO_RANDOM, resp.length, length);
        return resp;
    }

    /**
     * @param session An authenticated session to communicate with the device over
     * @return The value of the device setting for 'forceAudit' option
     * @throws YHConnectionException              If the connection to the device fails
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public static DeviceOptionValue getForceAudit(@NonNull final YHSession session)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        ByteBuffer data = ByteBuffer.allocate(1);
        data.put(DeviceOption.FORCE_AUDIT.getTag());
        byte[] resp = session.sendSecureCmd(Command.GET_OPTION, data.array());
        CommandUtils.verifyResponseLength(Command.GET_OPTION, resp.length, DEVICE_OPTION_VALUE_SIZE);
        DeviceOptionValue ret = DeviceOptionValue.forValue(resp[0]);
        log.info("Got device setting for " + DeviceOption.FORCE_AUDIT.getDescription() + ": " + ret.getDescription());
        return ret;
    }

    /**
     * Sets the value of device setting for 'forceAudit' option
     *
     * @param session         An authenticated session to communicate with the device over
     * @param forceAuditValue
     * @throws YHConnectionException              If the connection to the device fails
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public static void setForceAudit(@NonNull final YHSession session, @NonNull final DeviceOptionValue forceAuditValue)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        ByteBuffer data = ByteBuffer.allocate(4);
        data.put(DeviceOption.FORCE_AUDIT.getTag());
        data.putShort((short) 1);
        data.put(forceAuditValue.getValue());
        byte[] resp = session.sendSecureCmd(Command.SET_OPTION, data.array());
        CommandUtils.verifyResponseLength(Command.SET_OPTION, resp.length, 0);
        log.info("Set device setting for " + DeviceOption.FORCE_AUDIT.getDescription() + " to " + forceAuditValue.getDescription());
    }

    /**
     * @param session An authenticated session to communicate with the device over
     * @return The value of the device setting for 'commandAudit' option
     * @throws YHConnectionException              If the connection to the device fails
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public static Map<Command, DeviceOptionValue> getCommandAudit(@NonNull final YHSession session)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        ByteBuffer data = ByteBuffer.allocate(1);
        data.put(DeviceOption.COMMAND_AUDIT.getTag());
        byte[] resp = session.sendSecureCmd(Command.GET_OPTION, data.array());
        if (resp.length % 2 != 0) {
            throw new YHInvalidResponseException("Response to GetCommandAudit command is expected to contains an even number of bytes");
        }
        log.info("Got device setting for " + DeviceOption.COMMAND_AUDIT.getDescription() + ": " + Utils.getPrintableBytes(resp));
        return Utils.geOptionTlvValue(resp);
    }

    /**
     * @param session         An authenticated session to communicate with the device over
     * @param commandValueMap
     * @throws YHConnectionException              If the connection to the device fails
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public static void setCommandAudit(@NonNull final YHSession session, @NonNull final Map<Command, DeviceOptionValue> commandValueMap)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {

        byte[] commandValueBytes = Utils.geOptionTlvValue(commandValueMap);

        ByteBuffer data = ByteBuffer.allocate(3 + commandValueBytes.length);
        data.put(DeviceOption.COMMAND_AUDIT.getTag());
        data.putShort((short) commandValueBytes.length);
        data.put(commandValueBytes);
        try {
            byte[] resp = session.sendSecureCmd(Command.SET_OPTION, data.array());
            CommandUtils.verifyResponseLength(Command.SET_OPTION, resp.length, 0);
        } catch (YHDeviceException e) {
            if (e.getYhError().equals(YHError.INVALID_DATA)) {
                String fixedCommands = getFixedAuditCommands(session, commandValueMap);
                if (!fixedCommands.equals("")) {
                    throw new IllegalArgumentException("Fail. Trying to change the FIX settings for the following commands: " + fixedCommands);
                } else {
                    throw e;
                }
            } else {
                throw e;
            }
        }
        log.info("Set device setting for " + DeviceOption.COMMAND_AUDIT.getDescription() + " to " + Utils.getPrintableBytes(commandValueBytes));
    }

    private static String getFixedAuditCommands(@NonNull final YHSession session, @NonNull final Map<Command, DeviceOptionValue> commandValueMap)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        String ret = "";
        Map<Command, DeviceOptionValue> deviceValues = getCommandAudit(session);
        for (Command c : commandValueMap.keySet()) {
            if (deviceValues.get(c).equals(DeviceOptionValue.FIX)) {
                ret += c.getName() + " ";
            }
        }
        return ret;
    }

    /**
     * Fetch all current entries from the device Log Store.
     *
     * @param session An authenticated session to communicate with the device over
     * @return All current entries from the device Log Store
     * @throws YHConnectionException              If the connection to the device fails
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public static LogData getAuditLogData(@NonNull final YHSession session)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        byte[] resp = session.sendSecureCmd(Command.GET_LOG_ENTRIES, null);
        ByteBuffer bb = ByteBuffer.wrap(resp);
        short unloggedBoot = bb.getShort();
        short unloggedAuth = bb.getShort();
        int nrOfEntries = (int) bb.get();
        if (bb.remaining() % LogEntry.LOG_ENTRY_SIZE != 0) {
            throw new IllegalArgumentException(
                    "Response to " + Command.GET_LOG_ENTRIES.getName() + " command is expected to be " + (nrOfEntries * LogEntry.LOG_ENTRY_SIZE + 5) +
                    " bytes long, but was " + resp.length + " bytes instead");
        }

        Map<Short, LogEntry> logEntries = new HashMap<Short, LogEntry>();
        for (int i = 0; i < nrOfEntries; i++) {
            byte[] logEntryBytes = new byte[LogEntry.LOG_ENTRY_SIZE];
            bb.get(logEntryBytes);
            LogEntry logEntry = new LogEntry(logEntryBytes);
            logEntries.put(logEntry.getItemNumber(), logEntry);
        }

        log.info("Retrieved " + nrOfEntries + " log entries from YubiHSM");
        return new LogData(unloggedBoot, unloggedAuth, logEntries);
    }

    /**
     * Set the last extracted log entry.
     * <p>
     * Inform the device what the last extracted log entry is so logs can be reused. Mostly of practical use when forced auditing is enabled
     *
     * @param session An authenticated session to communicate with the device over
     * @param index   The item number of the last extracted log entry
     * @throws YHConnectionException              If the connection to the device fails
     * @throws NoSuchAlgorithmException           If the message encryption/decryption fails
     * @throws InvalidKeyException                If the message encryption/decryption fails
     * @throws YHDeviceException                  If the device returns an error
     * @throws NoSuchPaddingException             If the message encryption/decryption fails
     * @throws BadPaddingException                If the message encryption/decryption fails
     * @throws YHAuthenticationException          If the session or message authentication fails
     * @throws InvalidAlgorithmParameterException If the message encryption/decryption fails
     * @throws YHInvalidResponseException         If the device returns a response that cannot be parsed
     * @throws IllegalBlockSizeException          If the message encryption/decryption fails
     */
    public static void setAuditLogIndex(@NonNull final YHSession session, final short index)
            throws YHConnectionException, NoSuchAlgorithmException, InvalidKeyException, YHDeviceException,
                   NoSuchPaddingException, BadPaddingException, YHAuthenticationException, InvalidAlgorithmParameterException,
                   YHInvalidResponseException, IllegalBlockSizeException {
        ByteBuffer data = ByteBuffer.allocate(2);
        data.putShort(index);
        byte[] resp = session.sendSecureCmd(Command.SET_LOG_INDEX, data.array());
        CommandUtils.verifyResponseLength(Command.SET_LOG_INDEX, resp.length, 0);
        log.info("Set log index to " + index);
    }
}
