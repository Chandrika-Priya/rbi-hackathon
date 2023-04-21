package com.thoughtworks.ondc.poc.pocwrapper.cache;

import net.sf.ehcache.Cache;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@ContextConfiguration(classes = ContextConfiguration.class)
class CacheHelperTest {

    private static CacheHelper cacheHelper;

    @InjectMocks
    public static CacheManagerConfig cacheManagerConfig;

    @Test
    void shouldReturnCacheOfTranslateCacheFile(){
        cacheManagerConfig.getCacheManager();
        cacheHelper = new CacheHelper();
        cacheHelper.cacheManagerConfig = cacheManagerConfig;
        Cache cache = cacheHelper.getAI4BharatCacheFile();

        assertEquals("translateCacheFile", cache.getName());
    }

    @Test
    void shouldReturnCacheOfRasaCacheFile(){
        cacheManagerConfig.getCacheManager();
        cacheHelper = new CacheHelper();
        cacheHelper.cacheManagerConfig = cacheManagerConfig;
        Cache cache = cacheHelper.getRasaCacheFile();

        assertEquals("contextCacheFile",cache.getName());
    }



}
