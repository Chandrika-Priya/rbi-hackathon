package com.thoughtworks.ondc.poc.pocwrapper.cache;

import net.sf.ehcache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;

@Configuration
@ImportResource("classpath:ehcache.xml")
public class CacheManagerConfig {

    @Bean
    public CacheManager getCacheManager(){
        return CacheManager.newInstance();
    }
}
