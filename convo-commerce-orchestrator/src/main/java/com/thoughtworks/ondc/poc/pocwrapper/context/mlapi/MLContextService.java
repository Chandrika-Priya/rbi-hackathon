package com.thoughtworks.ondc.poc.pocwrapper.context.mlapi;
import com.thoughtworks.ondc.poc.pocwrapper.context.RequestData;
import net.sf.ehcache.Cache;
import net.sf.ehcache.Element;
import com.thoughtworks.ondc.poc.pocwrapper.cache.CacheHelper;

import com.thoughtworks.ondc.poc.pocwrapper.context.ContextResponse;
import com.thoughtworks.ondc.poc.pocwrapper.context.ContextService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class MLContextService implements ContextService {

    @Autowired
    CacheHelper cacheHelper;

    @Autowired
    ModelMapper modelMapper;

    @Autowired
    MLContextWebClient mlContextWebClient;

    @Override
    public ContextResponse getContext(String contextInput, RequestData requestData) {
        MLContextResponse response;
        Cache cache = cacheHelper.getRasaCacheFile();
        MLContextResponse mlContextResponse = mlContextWebClient.getContext(contextInput,requestData);
        response = mlContextResponse;
        return modelMapper.map(response, ContextResponse.class);
    }

}
