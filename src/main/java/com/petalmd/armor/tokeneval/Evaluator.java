package com.petalmd.armor.tokeneval;

import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.util.concurrent.ThreadContext;

import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by jehuty0shift on 09/01/2020.
 */
public class Evaluator implements Serializable {

    protected static final Logger log = LogManager.getLogger(Evaluator.class);


    /**
     *
     */
    private static final long serialVersionUID = 1L;
    private final Map<String, EntityFilters> indicesFilters;
    private final Map<String, EntityFilters> aliasFilters;
    private EntityFilters defaultFilters;

    public Evaluator(final List<String> requestedIndices, final List<String> requestedAliases) throws MalformedConfigurationException {
        super();
        this.indicesFilters = new HashMap<>();
        this.aliasFilters = new HashMap<>();

        //fill indicesFiltersMap
        requestedIndices.stream().forEach(index -> indicesFilters.put(index, new EntityFilters()));
        requestedAliases.stream().forEach(alias -> aliasFilters.put(alias, new EntityFilters()));
        this.defaultFilters = null;
    }

    public void setDefaultFilter(EntityFilters defaultFilter) throws MalformedConfigurationException {
        if (this.defaultFilters != null) {
            throw new MalformedConfigurationException("More than one default configuration found");
        }
        this.defaultFilters = defaultFilter;
    }

    public EntityFilters getDefaultFilters() {
        return defaultFilters;
    }

    public void addIndexFilters(String index, EntityFilters indexFilters) throws MalformedConfigurationException {
        indicesFilters.get(index).addEntityFilters(indexFilters);
    }

    public void addAliasFilters(String alias, EntityFilters aliasFilters) throws MalformedConfigurationException {
        this.aliasFilters.get(alias).addEntityFilters(aliasFilters);
    }


    public EvalResult evaluateDLS(final List<String> filters) {

        Set<String> execFilters = new HashSet<>();

        for (Map.Entry<String, EntityFilters> indexFilter : indicesFilters.entrySet()) {
            String index = indexFilter.getKey();
            EntityFilters eFilters = indexFilter.getValue();
            log.debug("evaluating DLS filters for index {}", index);
            execFilters.addAll(executeDLSFilterForItem(eFilters, filters));
        }

        for (Map.Entry<String, EntityFilters> aliasFilter : aliasFilters.entrySet()) {
            String alias = aliasFilter.getKey();
            EntityFilters eFilters = aliasFilter.getValue();
            log.debug("evaluating DLS filters for index {}", alias);
            execFilters.addAll(executeDLSFilterForItem(eFilters, filters));
        }


        return new EvalResult("all", EvalResult.Status.ALLOWED, execFilters);
    }


    private List<String> executeDLSFilterForItem(final EntityFilters eFilters, final List<String> filters) {

        Set<String> mergedFilters = eFilters.mergeDLSFilters();

        if (mergedFilters.isEmpty()) {
            mergedFilters = defaultFilters.mergeDLSFilters();
        }

        List<String> allowedDLSFilters = new ArrayList<>();
        for (String ft : mergedFilters) {
            allowedDLSFilters.addAll(filters.stream().filter(f -> SecurityUtil.isWildcardMatch(f, ft, false)).collect(Collectors.toList()));
        }

        return allowedDLSFilters;
    }

    public EvalResult evaluateFLS(final List<String> filters) {

        Set<String> execFilters = new HashSet<>();

        for (Map.Entry<String, EntityFilters> indexFilter : indicesFilters.entrySet()) {
            String index = indexFilter.getKey();
            EntityFilters eFilters = indexFilter.getValue();
            log.debug("evaluating FLS filters for index {}", index);
            execFilters.addAll(executeFLSFilterForItem(eFilters, filters));
        }

        for (Map.Entry<String, EntityFilters> aliasFilter : aliasFilters.entrySet()) {
            String alias = aliasFilter.getKey();
            EntityFilters eFilters = aliasFilter.getValue();
            log.debug("evaluating FLS filters for index {}", alias);
            execFilters.addAll(executeFLSFilterForItem(eFilters, filters));
        }


        return new EvalResult("all", EvalResult.Status.ALLOWED, execFilters);
    }


    private List<String> executeFLSFilterForItem(final EntityFilters eFilters, final List<String> filters) {

        Set<String> mergedFilters = eFilters.mergeFLSFilters();

        if (mergedFilters.isEmpty()) {
            mergedFilters = defaultFilters.mergeFLSFilters();
        }

        List<String> allowedFLSFilters = new ArrayList<>();
        for (String ft : mergedFilters) {
            allowedFLSFilters.addAll(filters.stream().filter(f -> SecurityUtil.isWildcardMatch(f, ft, false)).collect(Collectors.toList()));
        }

        return allowedFLSFilters;
    }

    //throw Forbidden exception if the action is not explicitely allowed
    public EvalResult evaluateAction(final String action, final List<String> filters, final List<String> additionalRights, final ThreadContext threadContext) {

        // Take action and filter list
        // Evaluate which filters to execute for each item
        // check each item has rule or go to default rule.
        // 2/ Normal Rule if it's forbidden, deny it, if not explicitly allowed, go to default. If allowed (that's okay)
        // 1/ Default rule : If its forbidden or not explicitly allowed, forbid it

        //check Indices
        for (Map.Entry<String, EntityFilters> indexFilter : indicesFilters.entrySet()) {
            String index = indexFilter.getKey();
            EntityFilters eFilters = indexFilter.getValue();
            log.debug("evaluating filters for index {}", index);
            Optional<EvalResult> filtersResult = allowedActionForItem(index, eFilters, action, filters, additionalRights, threadContext);
            if (filtersResult.isPresent()) {
                return filtersResult.get();
            }
        }

        //check aliases
        for (Map.Entry<String, EntityFilters> aliasFilter : aliasFilters.entrySet()) {
            String alias = aliasFilter.getKey();
            EntityFilters eFilters = aliasFilter.getValue();
            log.debug("evaluating filters for alias {}", alias);
            Optional<EvalResult> filtersResult = allowedActionForItem(alias, eFilters, action, filters, additionalRights, threadContext);
            if (filtersResult.isPresent()) {
                return filtersResult.get();
            }
        }


        return new EvalResult("all", EvalResult.Status.ALLOWED);
    }

    private Optional<EvalResult> allowedActionForItem(final String item, final EntityFilters eFilters, final String action, final List<String> filters, final List<String> additionalRights, final ThreadContext threadContext) {
        Set<String> mergeFilters = eFilters.mergeActionFilters();

        if (mergeFilters.isEmpty()) {
            if (!allowedActionForDefault(action, filters, additionalRights, threadContext)) {
                log.warn("Action '{}' is forbidden due to {}", action, "DEFAULT");
                return Optional.of(new EvalResult(item, EvalResult.Status.FORBIDDEN, Set.of("DEFAULT")));
            } else {
                //allowed for default, allow for Item
                return Optional.empty();
            }
        }

        for (String filter : filters) {
            if (mergeFilters.stream().filter(ft -> SecurityUtil.isWildcardMatch(filter, ft, false)).findAny().isPresent()) {
                List<String> allowedActions = threadContext.getTransient("armor." + filter + ".allowed_actions");
                if (allowedActions == null) {
                    allowedActions = Collections.emptyList();
                }

                List<String> forbiddenActions = threadContext.getTransient("armor." + filter + ".forbidden_actions");
                if (forbiddenActions == null) {
                    forbiddenActions = Collections.emptyList();
                }

                for (String forbiddenAction : forbiddenActions) {
                    if (SecurityUtil.isWildcardMatch(action, forbiddenAction, false)) {
                        log.debug("the action {}  is explicitly forbidden by filter", action, filter);
                        return Optional.of(new EvalResult(item, EvalResult.Status.FORBIDDEN, Set.of(filter)));
                    }
                }
                boolean allowed = false;
                for (final String allowedAction : allowedActions) {
                    String allowedActionSpecial = allowedAction;
                    for (String additionalRight : additionalRights) {
                        if (allowedAction.startsWith(additionalRight)) {
                            allowedActionSpecial = allowedAction.substring(additionalRight.length() + 1); //escape also the ':' separator
                        }
                    }
                    if (SecurityUtil.isWildcardMatch(action, allowedActionSpecial, false)) {
                        log.debug("the action {} is allowed by special action {}", action, filter);
                        allowed = true;
                        break;
                    }
                }
                if (!allowed && !allowedActionForDefault(action, filters, additionalRights, threadContext)) {
                    return Optional.of(new EvalResult(item, EvalResult.Status.FORBIDDEN, Set.of("DEFAULT")));
                }
            }
        }
        return Optional.empty();
    }

    private boolean allowedActionForDefault(final String action, final List<String> filters, final List<String> additionalRights, final ThreadContext threadContext) {
        Set<String> mergedFilters = defaultFilters.mergeActionFilters();

        for (String filter : filters) {
            if (mergedFilters.stream().filter(ft -> SecurityUtil.isWildcardMatch(filter, ft, false)).findAny().isPresent()) {
                List<String> allowedActions = threadContext.getTransient("armor." + filter + ".allowed_actions");
                if (allowedActions == null) {
                    allowedActions = Collections.emptyList();
                }

                List<String> forbiddenActions = threadContext.getTransient("armor." + filter + ".forbidden_actions");
                if (forbiddenActions == null) {
                    forbiddenActions = Collections.emptyList();
                }

                for (String forbiddenAction : forbiddenActions) {
                    if (SecurityUtil.isWildcardMatch(action, forbiddenAction, false)) {
                        log.debug("the action {} is explicitly forbidden by DEFAULT filter", action);
                        return false;
                    }
                }

                for (final String allowedAction : allowedActions) {
                    String allowedActionSpecial = allowedAction;
                    for (String additionalRight : additionalRights) {
                        if (allowedAction.startsWith(additionalRight)) {
                            allowedActionSpecial = allowedAction.substring(additionalRight.length() + 1); //escape also the ':' separator
                        }
                    }
                    if (SecurityUtil.isWildcardMatch(action, allowedActionSpecial, false)) {
                        log.debug("the action {} is allowed by special action on DEFAULT", action);
                        return true;
                    }
                }
            }
        }
        log.warn("action {} is not explicitly allowed by DEFAULT, will reject", action);
        return false;

    }

    public void validateAndMerge() throws MalformedConfigurationException {
//
//        if (!Collections.disjoint(bypassFilters, executeFilters)) {
//            log.warn("Identical execute and bypass filters");
//            log.warn("    bypassFilters: {}", bypassFilters);
//            log.warn("    executeFilters: {}", executeFilters);
//        }
//
//        if (bypassFilters.isEmpty() && executeFilters.isEmpty()) {
//            throw new MalformedConfigurationException("no bypass or execute filters at all");
//        }
    }
//
//    public boolean getBypassAll() {
//        return bypassFilters.contains("*");
//    }
//
//    public boolean getExecuteAll() {
//
//        return executeFilters.contains("*") && bypassFilters.isEmpty();
//
//    }
//
//    public TokenEvaluator.FilterAction evaluateFilter(final String ft, final String fn) {
//
//        final String filter = ft + "." + fn;
//
//        if (getExecuteAll()) {
//            return TokenEvaluator.FilterAction.EXECUTE;
//        }
//
//        if (getBypassAll()) {
//            return TokenEvaluator.FilterAction.BYPASS;
//        }
//
//        if (containsWildcardPattern(bypassFilters, filter)) {
//            return TokenEvaluator.FilterAction.BYPASS;
//        }
//
//        if (containsWildcardPattern(executeFilters, filter) || executeFilters.contains("*")) {
//            return TokenEvaluator.FilterAction.EXECUTE;
//        }
//
//        return TokenEvaluator.FilterAction.BYPASS;
//    }

}

