package com.thoughtworks.ondc.poc.pocwrapper.translation;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class TranslationControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TranslationService translationService;

    @Test
    public void shouldTranslateHindiToEnglish() throws Exception {
        String text = "कश्मीरी सेब-प्रति किलोग्राम"; //not sure what text and response holds
        String response = "Kashmiri Apple - per Kg";

        when(translationService.translateFromHindiToEnglish(text)).thenReturn(response);

        MvcResult mvcResult = mockMvc.perform(get("/v1/translate/hindi")
                        .param("text",text))
                .andExpect(status().isOk())
                .andReturn();

        String actualResponseBody = mvcResult.getResponse().getContentAsString();
        assertEquals(actualResponseBody,response);
    }

    @Test
    public void shouldTranslateIndicToEnglish() throws Exception {
        String text = "कश्मीरी सेब-प्रति किलोग्राम"; //not sure what text and response holds
        String source = "hi";
        String response = "Kashmiri Apple - per Kg";

        when(translationService.translateFromIndicToEnglish(text,source)).thenReturn(response);

        MvcResult mvcResult = mockMvc.perform(get("/v1/translate/i2e")
                        .param("text",text)
                .param("source",source))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();

        String actualResponseBody = mvcResult.getResponse().getContentAsString();
        assertEquals(actualResponseBody,response);
    }

    @Test
    public void shouldGetIndicFromEnglish() throws Exception {
        String target = "hi";
        String texts = "Kashmiri Apple - per Kg";
        String response = "कश्मीरी सेब-प्रति किलोग्राम";

        when(translationService.translateFromEnglishToIndic(texts,target)).thenReturn(response);

        mockMvc.perform(post("/v1/translate/e2i?target=hi")
                .contentType(MediaType.TEXT_PLAIN_VALUE)
                .content(texts))
                .andExpect(status().isOk());
    }

}
