package com.thoughtworks.ondc.poc.pocwrapper.context;

import org.springframework.stereotype.Service;

@Service
public interface ContextService {

    public ContextResponse getContext(String contextInput,RequestData requestData);

}
