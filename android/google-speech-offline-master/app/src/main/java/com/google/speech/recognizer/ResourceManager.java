// 
// Decompiled by Procyon v0.5.36
// 

package com.google.speech.recognizer;

public class ResourceManager
{
    public long nativeObj;
    
    public ResourceManager() {
        this.nativeObj = this.nativeConstruct();
    }
    
    private native long nativeConstruct();
    
    private native void nativeDelete(final long nativeObj);
    
    private native int nativeInitFromProto(final long nativeObj, final byte[] model_config, final String[] model_paths);
    
    public final int init(final byte[] config, final String[] models) {
        final long a = this.nativeObj;
        if (a != 0L) {
            //return fgg.instanceId(this.nativeInitFromProto(instanceId, array, array2));
            return this.nativeInitFromProto(a, config, models);
        }
        throw new IllegalStateException("recognizer is not initialized");
    }
    
    public final void delete() {
        synchronized (this) {
            if (this.nativeObj != 0L) {
                this.nativeDelete(this.nativeObj);
                this.nativeObj = 0L;
            }
        }
    }
    
    @Override
    protected void finalize() {
        this.delete();
    }
}
