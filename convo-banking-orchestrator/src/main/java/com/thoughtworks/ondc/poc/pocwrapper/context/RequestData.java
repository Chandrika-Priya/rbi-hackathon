package com.thoughtworks.ondc.poc.pocwrapper.context;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import javax.annotation.Nullable;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class RequestData {
    @Nullable
    private String nick_name;
    @Nullable
    private String full_name;
    @Nullable
    private String upi_id;
    @Nullable
    private String mob_number;
    @Nullable
    private String pin_number;
    @Nullable
    private String user_name;
}
