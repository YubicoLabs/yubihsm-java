package com.yubico.hsm.yhdata;

import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Command;
import lombok.NonNull;

import java.nio.ByteBuffer;

/**
 * This class represents a log entry as retrieved from a YubiHSM.
 * <p>
 * When the device initializes after a reset, a log entry with all fields set to 0xff is logged.
 * <p>
 * When the device boots up, a log entry with all fields set to 0x00 is logged.
 */
public class LogEntry {

    /** The size of one log entry in bytes */
    public static final int LOG_ENTRY_SIZE = 32; // 2 bytes itemNumber + 1 byte commandId + 2 bytes commandLength + 2 bytes sessionId + 2 bytes
    // targetKeyId + 2 bytes targetKeyId2 + 1 byte commandErrorCode + 4 bytes systick + 16 bytes entryDigest

    /** The size of the log entry digest in bytes */
    public static final int LOG_ENTRY_DIGEST_SIZE = 16;

    /** Generic log entry composed of the command number */
    private short itemNumber;
    private byte commandId;
    private short commandLength;
    /** The Session originating the command */
    private short sessionKeyId;
    /** The target key affected by the command */
    private short targetKeyId;
    /** A secondary key if the command affected more than one key */
    private short targetKeyId2;
    /** The result of the command. If the command was unsuccessful, the result is the error code */
    private byte commandErrorCode;
    /** The systick when the command was processed */
    private int systick;
    /** The entry digest. The digest is computed as trunc(16, SHA256(Ei || trunc(16, SHA256(Ei-1)))). For the initial log entry, a random string of 32 bytes is used, instead of the digest of the previous message */
    private byte[] entryDigest;

    public LogEntry(final short itemNumber, final byte commandId, final short commandLength, final short sessionKeyId, final short targetKeyId,
                    final short targetKeyId2, final byte commandErrorCode, final int systick, final byte[] entryDigest) {
        this.itemNumber = itemNumber;
        this.commandId = commandId;
        this.commandLength = commandLength;
        this.sessionKeyId = sessionKeyId;
        this.targetKeyId = targetKeyId;
        this.targetKeyId2 = targetKeyId2;
        this.commandErrorCode = commandErrorCode;
        this.systick = systick;
        this.entryDigest = entryDigest;
    }

    /**
     * Creates a LogEntry object by parsing the byte array
     *
     * @param logEntryData Byte array in the format: 2 bytes item number, 1 byte command ID, 2 bytes command length, 2 bytes session ID, 2 bytes
     *                     target key ID, 2 bytes second target key ID, 1 byte command result (or error code), 4 bytes systick, 16 bytes entryDigest
     */
    public LogEntry(@NonNull final byte[] logEntryData) {
        if (logEntryData.length != LOG_ENTRY_SIZE) {
            throw new IllegalArgumentException("Log entry expected to be " + LOG_ENTRY_SIZE + " bytes long, but was " + logEntryData.length);
        }

        ByteBuffer bb = ByteBuffer.wrap(logEntryData);
        this.itemNumber = bb.getShort();
        this.commandId = bb.get();
        this.commandLength = bb.getShort();
        this.sessionKeyId = bb.getShort();
        this.targetKeyId = bb.getShort();
        this.targetKeyId2 = bb.getShort();
        this.commandErrorCode = bb.get();
        this.systick = bb.getInt();
        entryDigest = new byte[LOG_ENTRY_DIGEST_SIZE];
        bb.get(entryDigest);

    }

    public short getItemNumber() {
        return itemNumber;
    }

    public byte getCommandId() {
        return commandId;
    }

    public short getCommandLength() {
        return commandLength;
    }

    public short getSessionKeyId() {
        return sessionKeyId;
    }

    public short getTargetKeyId() {
        return targetKeyId;
    }

    public short getTargetKeyId2() {
        return targetKeyId2;
    }

    public byte getCommandErrorCode() {
        return commandErrorCode;
    }

    public int getSystick() {
        return systick;
    }

    public byte[] getEntryDigest() {
        return entryDigest;
    }

    public String toString() {
        String.valueOf(sessionKeyId);
        return String.format("item: %4s -- cmd: %25s -- length: %3s -- session key: 0x%04x --  target key: 0x%04x -- second key: 0x%04x -- result: " +
                             "0x%02x -- tick: %6s -- hash: %s\n", itemNumber, Command.forId(commandId).getName(), commandLength, sessionKeyId,
                             targetKeyId, targetKeyId2, commandErrorCode, systick, Utils.getPrintableBytes(entryDigest));
    }
}

