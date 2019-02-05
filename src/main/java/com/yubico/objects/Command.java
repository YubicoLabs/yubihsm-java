package com.yubico.objects;

import java.util.HashMap;
import java.util.Map;

public class Command {

    public static final Command ECHO = new Command((byte) 0x01, "Echo");
    public static final Command CREATE_SESSION = new Command((byte) 0x03, "Create Session");
    public static final Command AUTHENTICATE_SESSION = new Command((byte) 0x04, "Authenticate Session");
    public static final Command SESSION_MESSAGE = new Command((byte) 0x05, "Session Message");
    public static final Command DEVICE_INFO = new Command((byte) 0x06, "Get Device Info");
    public static final Command RESET_DEVICE = new Command((byte) 0x08, "Reset Device");
    public static final Command CLOSE_SESSION = new Command((byte) 0x40, "Close Session");
    public static final Command GET_STORAGE_INFO = new Command((byte) 0x041, "Get Storage Info");
    public static final Command PUT_OPAQUE = new Command((byte) 0x42, "Put Opaque");
    public static final Command GET_OPAQUE = new Command((byte) 0x43, "Get Opaque");
    public static final Command PUT_AUTHENTICATION_KEY = new Command((byte) 0x44, "Put Authentication Key");
    public static final Command PUT_ASYMMETRIC_KEY = new Command((byte) 0x45, "Put Asymmetric Key");
    public static final Command GENERATE_ASYMMETRIC_KEY = new Command((byte) 0x46, "Generate Asymmetric Key");
    public static final Command SIGN_PKCS1 = new Command((byte) 0x47, "Sign Pkcs1");
    public static final Command LIST_OBJECTS = new Command((byte) 0x48, "List Objects");
    public static final Command DECRYPT_PKCS1 = new Command((byte) 0x49, "Decrypt Pkcs1");
    public static final Command EXPORT_WRAPPED = new Command((byte) 0x4a, "Export Wrapped");
    public static final Command IMPORT_WRAPPED = new Command((byte) 0x4b, "Import Wrapped");
    public static final Command PUT_WRAP_KEY = new Command((byte) 0x4c, "Put Wrap Key");
    public static final Command GET_LOG_ENTRIES = new Command((byte) 0x4d, "Get Log Entries");
    public static final Command GET_OBJECT_INFO = new Command((byte) 0x4e, "Get Object Info");
    public static final Command SET_OPTION = new Command((byte) 0x4f, "Set Option");
    public static final Command GET_OPTION = new Command((byte) 0x50, "Get Option");
    public static final Command GET_PSEUDO_RANDOM = new Command((byte) 0x51, "Get Pseudo Random");
    public static final Command PUT_HMAC_KEY = new Command((byte) 0x52, "Put Hmac Key");
    public static final Command SIGN_HMAC = new Command((byte) 0x53, "Sign Hmac");
    public static final Command GET_PUBLIC_KEY = new Command((byte) 0x54, "Get Public Key");
    public static final Command SIGN_PSS = new Command((byte) 0x55, "Sign Pss");
    public static final Command SIGN_ECDSA = new Command((byte) 0x56, "Sign Ecdsa");
    public static final Command DERIVE_ECDH = new Command((byte) 0x57, "Derive Ecdh");
    public static final Command DELETE_OBJECT = new Command((byte) 0x58, "Delete Object");
    public static final Command DECRYPT_OAEP = new Command((byte) 0x59, "Decrypt Oaep");
    public static final Command GENERATE_HMAC_KEY = new Command((byte) 0x5a, "Generate Hmac Key");
    public static final Command GENERATE_WRAP_KEY = new Command((byte) 0x5b, "Generate Wrap Key");
    public static final Command VERIFY_HMAC = new Command((byte) 0x5c, "Verify Hmac");
    public static final Command SIGN_SSH_CERTIFICATE = new Command((byte) 0x5d, "Sign Ssh Certificate");
    public static final Command PUT_TEMPLATE = new Command((byte) 0x5e, "Put Template");
    public static final Command GET_TEMPLATE = new Command((byte) 0x5f, "Get Template");
    public static final Command DECRYPT_OTP = new Command((byte) 0x60, "Decrypt Otp");
    public static final Command CREATE_OTP_AEAD = new Command((byte) 0x61, "Create Otp Aead");
    public static final Command RANDOMIZE_OTP_AEAD = new Command((byte) 0x62, "Randomize Otp Aead");
    public static final Command REWRAP_OTP_AEAD = new Command((byte) 0x63, "Rewrap Otp Aead");
    public static final Command SIGN_ATTESTATION_CERTIFICATE = new Command((byte) 0x64, "Sign Attestation Certificate");
    public static final Command PUT_OTP_AEAD_KEY = new Command((byte) 0x65, "Put Otp Aead Key");
    public static final Command GENERATE_OTP_AEAD_KEY = new Command((byte) 0x66, "Generate Otp Aead Key");
    public static final Command SET_LOG_INDEX = new Command((byte) 0x67, "Set Log Index");
    public static final Command WRAP_DATA = new Command((byte) 0x68, "Wrap Data");
    public static final Command UNWRAP_DATA = new Command((byte) 0x69, "Unwrap Data");
    public static final Command SIGN_EDDSA = new Command((byte) 0x6a, "Sign Eddsa");
    public static final Command BLINK_DEVICE = new Command((byte) 0x6b, "Blink Device");
    public static final Command CHANGE_AUTHENTICATION_KEY = new Command((byte) 0x6c, "Change Authentication Key");
    public static final Command ERROR = new Command((byte) 0x7f, "Error");

    private byte command;
    private String name;

    public Command(final byte command, final String name) {
        this.command = command;
        this.name = name;
    }

    public byte getCommand() {
        return command;
    }

    public String getName() {
        return name;
    }

    public byte getCommandResponse() {
        return (byte) (command | 0x80);
    }

    public boolean isError() {
        return command == ERROR.getCommand();
    }

    public static boolean isError(final byte command) {
        return command == ERROR.getCommand();
    }

    public static String getNameFromCommand(final byte command) {
        final Command cmd = (Command) getCommandsMap().get(command);
        if (cmd != null) {
            return cmd.getName();
        }
        return String.format("Command 0x%02X not supported", command);
    }

    public static Command getCommand(final byte command) {
        return (Command) getCommandsMap().get(command);
    }

    public static boolean isSupportedCommand(final byte command) {
        return getCommandsMap().containsKey(command);
    }

    public String toString() {
        return String.format("0x%02X: " + name, command);
    }

    public boolean equals(final Command other) {
        return this.getCommand() == other.getCommand();
    }

    private static Map getCommandsMap() {
        Map commands = new HashMap();
        commands.put((byte) 0x01, ECHO);
        commands.put((byte) 0x03, CREATE_SESSION);
        commands.put((byte) 0x04, AUTHENTICATE_SESSION);
        commands.put((byte) 0x05, SESSION_MESSAGE);
        commands.put((byte) 0x06, DEVICE_INFO);
        commands.put((byte) 0x08, RESET_DEVICE);
        commands.put((byte) 0x40, CLOSE_SESSION);
        commands.put((byte) 0x41, GET_STORAGE_INFO);
        commands.put((byte) 0x42, PUT_OPAQUE);
        commands.put((byte) 0x43, GET_OPAQUE);
        commands.put((byte) 0x44, PUT_AUTHENTICATION_KEY);
        commands.put((byte) 0x45, PUT_ASYMMETRIC_KEY);
        commands.put((byte) 0x46, GENERATE_ASYMMETRIC_KEY);
        commands.put((byte) 0x47, SIGN_PKCS1);
        commands.put((byte) 0x48, LIST_OBJECTS);
        commands.put((byte) 0x49, DECRYPT_PKCS1);
        commands.put((byte) 0x4a, EXPORT_WRAPPED);
        commands.put((byte) 0x4b, IMPORT_WRAPPED);
        commands.put((byte) 0x4c, PUT_WRAP_KEY);
        commands.put((byte) 0x4d, GET_LOG_ENTRIES);
        commands.put((byte) 0x4e, GET_OBJECT_INFO);
        commands.put((byte) 0x4f, SET_OPTION);
        commands.put((byte) 0x50, GET_OPTION);
        commands.put((byte) 0x51, GET_PSEUDO_RANDOM);
        commands.put((byte) 0x52, PUT_HMAC_KEY);
        commands.put((byte) 0x53, SIGN_HMAC);
        commands.put((byte) 0x54, GET_PUBLIC_KEY);
        commands.put((byte) 0x55, SIGN_PSS);
        commands.put((byte) 0x56, SIGN_ECDSA);
        commands.put((byte) 0x57, DERIVE_ECDH);
        commands.put((byte) 0x58, DELETE_OBJECT);
        commands.put((byte) 0x59, DECRYPT_OAEP);
        commands.put((byte) 0x5a, GENERATE_HMAC_KEY);
        commands.put((byte) 0x5b, GENERATE_WRAP_KEY);
        commands.put((byte) 0x5c, VERIFY_HMAC);
        commands.put((byte) 0x5d, SIGN_SSH_CERTIFICATE);
        commands.put((byte) 0x5e, PUT_TEMPLATE);
        commands.put((byte) 0x5f, GET_TEMPLATE);
        commands.put((byte) 0x60, DECRYPT_OTP);
        commands.put((byte) 0x61, CREATE_OTP_AEAD);
        commands.put((byte) 0x62, RANDOMIZE_OTP_AEAD);
        commands.put((byte) 0x63, REWRAP_OTP_AEAD);
        commands.put((byte) 0x64, SIGN_ATTESTATION_CERTIFICATE);
        commands.put((byte) 0x65, PUT_OTP_AEAD_KEY);
        commands.put((byte) 0x66, GENERATE_OTP_AEAD_KEY);
        commands.put((byte) 0x67, SET_LOG_INDEX);
        commands.put((byte) 0x68, WRAP_DATA);
        commands.put((byte) 0x69, UNWRAP_DATA);
        commands.put((byte) 0x6a, SIGN_EDDSA);
        commands.put((byte) 0x6b, BLINK_DEVICE);
        commands.put((byte) 0x6c, CHANGE_AUTHENTICATION_KEY);
        return commands;
    }
}
