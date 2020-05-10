package com.google.speech.recognizer;

import android.util.Log;

import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.UnknownFieldSet;
import com.google.protobuf.UnknownFieldSetLite;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.logging.Logger;

public class AbstractRecognizer {

    private static final Logger logger = Logger.getLogger(AbstractRecognizer.class.getName());

    static public String TAG = "AbstractRecognizer";

    public InputStream reader;
    private long nativeObj;

    private static

    FileOutputStream lhandleEndpointerEvent;
    FileOutputStream lhandleRecognitionEvent;

    static {

    }

    private native int nativeCancel(final long nativeObj);

    private native long nativeConstruct();

    private native void nativeDelete(final long nativeObj);

    private native int nativeInitFromProto(final long nativeObj, final long resourceNativeObj, final byte[] config);

    private native byte[] nativeRun(final long nativeObj, final byte[] params);

    private native void nativeInit(final long nativeObj);

    public AbstractRecognizer() {
        this.nativeObj = this.nativeConstruct();
    }

    public static String print(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ ");
        for (byte b : bytes) {
            sb.append(String.format("0x%02X ", b));
        }
        sb.append("]");
        return sb.toString();
    }

    private final void validate() {
        if (this.nativeObj != 0L) {
            return;
        }
        throw new IllegalStateException("recognizer is not initialized");
    }

    public final byte[] run(final byte[] params) {
        this.validate();
        final byte[] nativeRun = this.nativeRun(this.nativeObj, params);

        Log.d(TAG + " - nativeRun", bytesToHex(nativeRun));
        Log.d(TAG, new String(nativeRun, Charset.forName("UTF-8")));

        return nativeRun;
    }

    public final int init(final byte[] array, final ResourceManager resourceManager) {
        this.validate();
        return this.nativeInitFromProto(
                this.nativeObj,
                resourceManager.nativeObj,
                array
        );
    }

    public final void delete() {
        synchronized (this) {
            if (this.nativeObj != 0L) {
                this.nativeDelete(this.nativeObj);
                this.nativeObj = 0L;
            }
        }
    }

    public final int cancel() {
        this.validate();
        //return fgg.instanceId(this.nativeCancel(this.instanceId));
        return this.nativeCancel(this.nativeObj);
    }

    @Override
    protected void finalize() {
        this.delete();
    }

    protected void handleAudioLevelEvent(final byte[] array) {
        UnknownFieldSet set = null;
        try {
            set = UnknownFieldSet.parseFrom(array);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }
//        Log.d(TAG, String.format("handleAudioLevelEvent: %s", set.toString()));
    }

    protected void handleEndpointerEvent(final byte[] array) {

        Log.d(TAG, bytesToHex(array));

        try {
            lhandleEndpointerEvent.write("-next-".getBytes());
            lhandleEndpointerEvent.write(array);
        } catch (IOException e) {
            e.printStackTrace();
        }
        //https://stackoverflow.com/questions/7914034/how-to-decode-protobuf-binary-response
        try {
            Any any = Any.parseFrom(array);
            UnknownFieldSet set = UnknownFieldSet.parseFrom(array);

//            Log.d(TAG, String.format("handleEndpointerEvent: %s", set.toString()));
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

    }

    protected void handleHotwordEvent(final byte[] array) {
        UnknownFieldSet set = null;
        try {
            set = UnknownFieldSet.parseFrom(array);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }
//        Log.d(TAG, String.format("handleHotwordEvent: %s", set.toString()));
    }

    protected void handleRecognitionEvent(final byte[] array) {
        Log.d(TAG + " - handleRecognitionEvent", bytesToHex(array));
        try {
            lhandleRecognitionEvent.write("-next-".getBytes());
            lhandleRecognitionEvent.write(array);
        } catch (IOException e) {
            e.printStackTrace();
        }

        UnknownFieldSet set = null;
        try {
            set = UnknownFieldSet.parseFrom(array);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

//        Log.d(TAG, String.format("handleRecognitionEvent: %s", set.toString()));
//        Log.d(TAG, Arrays.toString(array));
//        Log.d(TAG, print(array));
//        Log.d(TAG, new String(array, Charset.forName("UTF-8")));

    }

    public static String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for(byte b : in) {
            builder.append(String.format("%02x ", b));
        }
        return builder.toString();
    }

    protected int read(final byte[] buffer) {

//        Log.d(TAG, String.format("AbstractRecognizer.read(%d)", buffer.length));

        if (buffer.length > 0) {
            int bytesRead = 0;
            try {
                bytesRead = this.reader.read(buffer);
//                Log.d(TAG, bytesToHex(buffer));
            } catch (IOException e) {
                e.printStackTrace();
            }
            return bytesRead == -1 ? 0 : bytesRead;
        }
        return -1;
    }

    protected void setAudioReader(InputStream audioStream) {
        reader = audioStream;
    }

    public void setLogFile(File sdcard) {

        try {
            lhandleEndpointerEvent = new FileOutputStream(new File (sdcard.getAbsolutePath() + String.format("/offline-speech/endpointer_%d.bin", this.nativeObj)));
            lhandleRecognitionEvent = new FileOutputStream(new File (sdcard.getAbsolutePath() + String.format("/offline-speech/recognition_%d.bin", this.nativeObj)));
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
