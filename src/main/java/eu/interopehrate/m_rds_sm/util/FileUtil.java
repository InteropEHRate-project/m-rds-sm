package eu.interopehrate.m_rds_sm.util;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class FileUtil {
    public static String LoadData(Context context, String fileName) throws IOException {
        BufferedReader reader = null;
        StringBuilder builder = new StringBuilder();
        try {
            InputStream stream = context.getAssets().open(fileName);
            reader = new BufferedReader(
                    new InputStreamReader(stream, "UTF-8"));

            int c;
            while ((c = reader.read()) != -1) {
                builder.append((char)c);
            }
        } catch (IOException e) {
            throw e;
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    Log.e("LoadData", "Failed to close stream " + e.getMessage());
                }
            }
        }
        return builder.toString();
    }

    public static void SaveData(Context context, String fileName, String data) throws IOException {
        try (FileOutputStream stream = new FileOutputStream(fileName)) {
            stream.write(data.getBytes());
        }
    }

}
