package com.google.android.apps.googlespeechoffline.speech;

import com.google.speech.recognizer.AbstractRecognizer;
import com.google.speech.recognizer.ResourceManager;

import java.io.Closeable;
import java.io.InputStream;

public class CustomRecognizer extends AbstractRecognizer implements Closeable
{
    public final ResourceManager mResourceManager = new CustomResourceManager();

    static {
        System.loadLibrary("google_speech_jni");
        System.loadLibrary("inject");
    }

    static public CustomRecognizer create(InputStream audioStream, byte[] dictationConfig, String model)
    {

        CustomRecognizer recognizer = new CustomRecognizer();

        recognizer.mResourceManager.init(dictationConfig, new String[] { model });
        recognizer.setAudioReader(audioStream);
        recognizer.init(dictationConfig, recognizer.mResourceManager);

        return recognizer;
    }

    @Override
    public final void close() {
        this.mResourceManager.delete();
    }
}