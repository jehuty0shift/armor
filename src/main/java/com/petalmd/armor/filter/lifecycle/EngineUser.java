package com.petalmd.armor.filter.lifecycle;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Created by jehuty0shift on 23/01/2020.
 */

public class EngineUser {
    public String username;
    public boolean trusted;
    public Region region;

}
