package com.google.android.apps.googlespeechoffline;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.apps.googlespeechoffline.speech.CustomRecognizer;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;

public class MainActivity extends AppCompatActivity {
    private static final int PERMISSION_REQUEST_CODE = 100;

    private Button runButton;
    private TextView debugTextView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        if (!checkPermission())
        {
            requestPermission();
        }

        debugTextView = (TextView) findViewById(R.id.debugTextView);

        runButton = (Button) findViewById(R.id.runButton);
        runButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View arg0) {
                debugTextView.setText("");
                File sdcard = Environment.getExternalStorageDirectory();

                File f = new File(sdcard.getAbsolutePath() + "/offline-speech/models/lp_rnnt-20181012/dictation.config");

                byte[] dictationConfig = new byte[(int)f.length()];
                BufferedInputStream buf = null;

                try {
                    buf = new BufferedInputStream(new FileInputStream(f));
                    buf.read(dictationConfig, 0, dictationConfig.length);
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }


                try {

                    final CustomRecognizer recognizer = CustomRecognizer.create(
                            new FileInputStream(new File(sdcard.getAbsolutePath() +"/offline-speech/samples/sample_hi_8000.wav")),
                            dictationConfig,
                            sdcard.getAbsolutePath() + "/offline-speech/models/lp_rnnt-20181012"
                    );

                    recognizer.setLogFile(sdcard);

                    Thread thread = new Thread() {
                        @Override
                        public void run() {
                            // i dont understand this params, kkkkk
                            final byte[] bytes = recognizer.run(new byte[] { 0x15, 0x00, 0x00, 0x7A, 0x46, 0x18, 0x01 });

                            runOnUiThread(new Runnable() {
                                public void run() {
                                    debugTextView.setText(new String(bytes, Charset.forName("UTF-8")));
                                }
                            });
                        }
                    };

                    thread.start();

                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                }
            }
        });
    }
    private boolean checkPermission() {
        int result = ContextCompat.checkSelfPermission(MainActivity.this, android.Manifest.permission.READ_EXTERNAL_STORAGE);
        if (result == PackageManager.PERMISSION_GRANTED) {
            return true;
        } else {
            return false;
        }
    }
    private void requestPermission() {
        if (ActivityCompat.shouldShowRequestPermissionRationale(MainActivity.this, android.Manifest.permission.READ_EXTERNAL_STORAGE)) {
            Toast.makeText(MainActivity.this, "Write External Storage permission allows us to read files. Please allow this permission in App Settings.", Toast.LENGTH_LONG).show();
        } else {
            ActivityCompat.requestPermissions(MainActivity.this, new String[]{android.Manifest.permission.READ_EXTERNAL_STORAGE}, PERMISSION_REQUEST_CODE);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String permissions[], int[] grantResults) {
        switch (requestCode) {
            case PERMISSION_REQUEST_CODE:
                if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Log.e("value", "Permission Granted, Now you can use local drive .");
            } else {
                Log.e("value", "Permission Denied, You cannot use local drive .");
            }
            break;
        }
    }
}
