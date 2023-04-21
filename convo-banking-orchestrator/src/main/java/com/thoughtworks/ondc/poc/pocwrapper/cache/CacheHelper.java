package com.thoughtworks.ondc.poc.pocwrapper.cache;

import net.sf.ehcache.Cache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CacheHelper {

    @Autowired
    public
    CacheManagerConfig cacheManagerConfig;

    public Cache getAI4BharatCacheFile() {
        return cacheManagerConfig.getCacheManager().getCache("translateCacheFile");
    }

    public Cache getRasaCacheFile(){
        return cacheManagerConfig.getCacheManager().getCache("contextCacheFile");
    }

}
