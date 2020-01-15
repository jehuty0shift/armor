package com.petalmd.armor.tokeneval;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Created by jehuty0shift on 14/01/2020.
 */
public class EvalResult {

    public enum Status {
        ALLOWED,
        FORBIDDEN
    }

    public Status result;
    public String item;
    public Set<String> filters;

    public EvalResult(String item, Status result){
        this.result = result;
        this.item = item;
        this.filters = Collections.emptySet();
    }

    public EvalResult(String item, Status result, Set<String> filters) {
        this.result = result;
        this.item = item;
        this.filters = filters;
    }

}
