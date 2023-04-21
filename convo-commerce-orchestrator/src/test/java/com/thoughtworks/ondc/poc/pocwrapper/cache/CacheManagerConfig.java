package com.thoughtworks.ondc.poc.pocwrapper.cache;

import net.sf.ehcache.CacheManager;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
@ContextConfiguration(classes = ContextConfiguration.class)
class CacheManagerConfigTest {

    @InjectMocks
    CacheManagerConfig cacheManagerConfig;

    @Test
    public void shouldCheckPresenceOfCacheManager() {
        CacheManager cacheManager = cacheManagerConfig.getCacheManager();
        assertNotNull(cacheManager);
    }
}
