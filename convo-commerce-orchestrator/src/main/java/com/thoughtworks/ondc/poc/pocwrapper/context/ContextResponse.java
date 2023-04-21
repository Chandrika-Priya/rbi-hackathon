package com.thoughtworks.ondc.poc.pocwrapper.context;

import com.thoughtworks.ondc.poc.pocwrapper.context.mlapi.MLContextResponse;
import lombok.*;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContextResponse {
    private NextStep nextStep;
    private List<Map<String, String>> data;

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    public static class NextStep {

        private String message;
        private List<Alternates> alternates;

        @Getter
        @Setter
        @NoArgsConstructor
        @AllArgsConstructor
        public static class Alternates {

            private String message;
            private BigDecimal confidence;

        }
    }
}
