package com.yubico.hsm.yhdata;

import lombok.NonNull;

import java.nio.ByteBuffer;
import java.util.*;

public class LogData {

    private short unloggedBootEvents;
    private short unloggedAuthenticationEvents;
    Map<Short, LogEntry> logEntries;

    public LogData(final short unloggedBootEvents, final short unloggedAuthenticationEvents, @NonNull final Map<Short, LogEntry> logEntries) {
        this.unloggedBootEvents = unloggedBootEvents;
        this.unloggedAuthenticationEvents = unloggedAuthenticationEvents;
        this.logEntries = logEntries;
    }

    /**
     * Creates a LogEntry object by parsing the byte array
     *
     * @param data Byte array in the format: 2 bytes unlogged boot events, 2 bytes unlogged authentication events, 1 byte the number of log
     *             entries, the log entries - each constructed as described in LogEntry
     */
    public LogData(@NonNull final byte[] data) {
        ByteBuffer bb = ByteBuffer.wrap(data);
        unloggedBootEvents = bb.getShort();
        unloggedAuthenticationEvents = bb.getShort();
        int nrOfEntries = (int) bb.get();
        if (bb.remaining() % LogEntry.LOG_ENTRY_SIZE != 0) {
            throw new IllegalArgumentException(
                    "The Log data is expected to be " + (nrOfEntries * LogEntry.LOG_ENTRY_SIZE + 5) + " bytes long, but was " + data.length +
                    " bytes instead");
        }

        logEntries = new HashMap<Short, LogEntry>();
        for (int i = 0; i < nrOfEntries; i++) {
            byte[] logEntryBytes = new byte[LogEntry.LOG_ENTRY_SIZE];
            bb.get(logEntryBytes);
            LogEntry logEntry = new LogEntry(logEntryBytes);
            logEntries.put(logEntry.getItemNumber(), logEntry);
        }
    }

    public short getUnloggedBootEvents() {
        return unloggedBootEvents;
    }

    public short getUnloggedAuthenticationEvents() {
        return unloggedAuthenticationEvents;
    }

    public Map<Short, LogEntry> getLogEntries() {
        return logEntries;
    }

    public LogEntry getLogEntry(final short itemNumber) {
        return logEntries.get(itemNumber);
    }

    /**
     * @return The log entry in 'logEntries' with the highest item number
     */
    public LogEntry getLastLogEntry() {
        List sortedIndex = getSortedEntriesIndex();
        return logEntries.get(sortedIndex.get(sortedIndex.size() - 1));
    }

    /**
     * @return The log entry in 'logEntries' with the lowest item number
     */
    public LogEntry getFirstLogEntry() {
        List sortedIndex = getSortedEntriesIndex();
        return logEntries.get(sortedIndex.get(0));
    }

    private List getSortedEntriesIndex() {
        ArrayList sortedEntries = new ArrayList(logEntries.keySet());
        Collections.sort(sortedEntries);
        return sortedEntries;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Unlogged boot events: " + unloggedBootEvents).append("\n");
        sb.append("Unlogged authentication events: " + unloggedAuthenticationEvents).append("\n");
        sb.append("Found " + logEntries.size() + " log entries: ").append("\n");
        for (LogEntry logEntry : logEntries.values()) {
            sb.append(logEntry);
        }
        return sb.toString();
    }
}
