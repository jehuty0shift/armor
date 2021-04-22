package com.petalmd.armor.filter.obfuscation;

import com.carrotsearch.hppc.cursors.ObjectObjectCursor;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.tokeneval.RulesEntities;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.indices.alias.get.GetAliasesResponse;
import org.elasticsearch.cluster.metadata.AliasMetadata;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class ObfGetAliasResponse implements ObfResponse {

    private static final Logger log = LogManager.getLogger(ObfGetAliasResponse.class);
    private final ThreadContext threadContext;
    private final GetAliasesResponse gar;

    public ObfGetAliasResponse(final GetAliasesResponse response, final Settings armorSettings, final ThreadContext threadContext) {
        this.gar = response;
        this.threadContext = threadContext;
    }

    private ImmutableOpenMap<String, List<AliasMetadata>> obfuscateAliasMetadata(ImmutableOpenMap<String, List<AliasMetadata>> aliasMDMap, ThreadContext threadContext) {

        final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
        ImmutableOpenMap.Builder<String, List<AliasMetadata>> obfAliasMDMap = ImmutableOpenMap.builder();
        if (user != null) {
            final TokenEvaluator tokenEval = threadContext.getTransient(ArmorConstants.ARMOR_TOKEN_EVALUATOR);
            if (tokenEval != null) {
                final RulesEntities rulesEntities = tokenEval.findEntitiesForUser(user);
                final Set<String> aliasesAllowed = rulesEntities.getAliases();
                for (Iterator<ObjectObjectCursor<String, List<AliasMetadata>>> it = aliasMDMap.iterator(); it.hasNext(); ) {
                    ObjectObjectCursor<String, List<AliasMetadata>> entry = it.next();
                    log.debug("GetAliasResponse obfuscating from index {} for user", entry.key, user.getName());
                    final List<AliasMetadata> aliasMDList = entry.value;
                    final List<AliasMetadata> newAliasMDList = new ArrayList<>();
                    for (AliasMetadata aliasMD : aliasMDList) {
                        final String alias = aliasMD.alias();
                        log.debug("checking if alias {} is allowed for user {}", alias, user.getName());
                        if (aliasesAllowed.stream().anyMatch(a -> SecurityUtil.isWildcardMatch(alias, a, false))) {
                            log.debug("alias {} is allowed for user {}", alias, user.getName());
                            newAliasMDList.add(aliasMD);
                        }
                    }
                    if (!newAliasMDList.isEmpty()) {
                        obfAliasMDMap.put(entry.key, newAliasMDList);
                    }
                }
            }
        }

        return obfAliasMDMap.build();
    }

    @Override
    public ActionResponse getActionResponse() {
        return new GetAliasesResponse(obfuscateAliasMetadata(gar.getAliases(), threadContext));
    }
}
