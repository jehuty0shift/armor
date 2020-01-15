package com.petalmd.armor.tokeneval;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by jehuty0shift on 09/01/2020.
 */
public class EntityFilters {

    private Set<String> bypassFilters;
    private Set<String> executeFilters;

    private static final String ACTION_FILTER_TYPE = "actionrequestfilter";
    private static final String DLS_FILTER_TYPE = "dlsfilter";
    private static final String FLS_FILTER_TYPE = "flsfilter";


    public EntityFilters(Set<String> bypassFilters, Set<String> executeFilters) {
        this.bypassFilters = bypassFilters;
        this.executeFilters = executeFilters;
    }

    public EntityFilters(TokenEvaluator.ACRule acRule) {
        this.bypassFilters = acRule.getFilters_bypass();
        this.executeFilters = acRule.getFilters_execute();
    }

    public EntityFilters() {
        this.bypassFilters = new HashSet<>();
        this.executeFilters = new HashSet<>();
    }

    public Set<String> getBypassFilters() {
        return bypassFilters;
    }

    public void setBypassFilters(Set<String> bypassFilters) {
        this.bypassFilters = bypassFilters;
    }

    public Set<String> getExecuteFilters() {
        return executeFilters;
    }

    public void setExecuteFilters(Set<String> executeFilters) {
        this.executeFilters = executeFilters;
    }

    public void addEntityFilters(EntityFilters entityActionFilters) throws MalformedConfigurationException{
        if(entityActionFilters.executeFilters.isEmpty() && entityActionFilters.bypassFilters.isEmpty()) {
            throw new MalformedConfigurationException("no bypass or execute filters at all");
        }
        this.executeFilters.addAll(entityActionFilters.executeFilters);
        this.bypassFilters.addAll(entityActionFilters.bypassFilters);
    }

    public Set<String> mergeActionFilters() {
        return mergeFiltersForType(ACTION_FILTER_TYPE);
    }

    public Set<String> mergeDLSFilters() {
        return mergeFiltersForType(DLS_FILTER_TYPE);
    }

    public Set<String> mergeFLSFilters() {
        return mergeFiltersForType(FLS_FILTER_TYPE);
    }

    private Set<String> mergeFiltersForType(final String type) {
        Set<String> merged = executeFilters.stream().filter(f -> f.equals("*") || (f.contains(type) && !bypassFilters.contains(f))).collect(Collectors.toSet());
        return merged;
    }
}
