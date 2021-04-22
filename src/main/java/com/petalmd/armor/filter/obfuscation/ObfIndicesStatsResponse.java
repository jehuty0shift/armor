package com.petalmd.armor.filter.obfuscation;

import com.petalmd.armor.authentication.User;
import com.petalmd.armor.tokeneval.RulesEntities;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.indices.stats.IndicesStatsAction;
import org.elasticsearch.action.admin.indices.stats.IndicesStatsResponse;
import org.elasticsearch.action.admin.indices.stats.ShardStats;
import org.elasticsearch.action.support.DefaultShardOperationFailedException;
import org.elasticsearch.action.support.broadcast.BroadcastResponse;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class ObfIndicesStatsResponse implements ObfResponse {

    private static final Logger log = LogManager.getLogger(ObfIndicesStatsResponse.class);
    private final ThreadContext threadContext;
    private final IndicesStatsResponse isr;

    public ObfIndicesStatsResponse(final IndicesStatsResponse isr, final Settings settings, final ThreadContext threadContext) {
        this.isr = isr;
        this.threadContext = threadContext;
    }

    private IndicesStatsResponse obfuscateIndicesStatsResponse(IndicesStatsResponse isr) {

        List<ShardStats> newShardStats = new ArrayList<>(isr.getShards().length);
        List<DefaultShardOperationFailedException> newFailedException = new ArrayList<>(isr.getShardFailures().length);

        final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
        if (user != null) {
            log.debug("obfuscating IndicesStatsResponse for user {}", user.getName());
            final TokenEvaluator tokenEval = threadContext.getTransient(ArmorConstants.ARMOR_TOKEN_EVALUATOR);
            if (tokenEval != null) {
                final RulesEntities rulesEntities = tokenEval.findEntitiesForUser(user);
                Set<String> indicesAllowed = rulesEntities.getIndices();
                Set<String> aliasAllowed = rulesEntities.getAliases();
                for (ShardStats shardStats : isr.getShards()) {
                    final String indexName = shardStats.getShardRouting().getIndexName();
                    if (indicesAllowed.stream().anyMatch(i -> SecurityUtil.isWildcardMatch(indexName, i, false))
                            || aliasAllowed.stream().anyMatch(a -> SecurityUtil.isWildcardMatch(indexName, a, false))) {
                        newShardStats.add(shardStats);
                    }
                }
                for (DefaultShardOperationFailedException dsofEx : isr.getShardFailures()) {
                    final String indexName = dsofEx.toString().split("\\[")[1].split("\\]")[0]; //toString format: [ + index + ]+[+shardId+]+....
                    if (indicesAllowed.stream().anyMatch(i -> SecurityUtil.isWildcardMatch(indexName, i, false))
                            || aliasAllowed.stream().anyMatch(a -> SecurityUtil.isWildcardMatch(indexName, a, false))) {
                        newFailedException.add(dsofEx);
                    }
                }
            }
        }

        int totalShards = newShardStats.size() + newFailedException.size();
        int successfulShards = newShardStats.size();
        int failedShards = newFailedException.size();

        BroadcastResponse brc = new BroadcastResponse(totalShards, successfulShards, failedShards, newFailedException);
        BytesStreamOutput bSO = new BytesStreamOutput();
        try {
            brc.writeTo(bSO);
            bSO.writeArray(newShardStats.stream().toArray(ShardStats[]::new));
            Writeable.Reader<IndicesStatsResponse> reader = IndicesStatsAction.INSTANCE.getResponseReader();
            IndicesStatsResponse newIsr = reader.read(bSO.bytes().streamInput());
            return newIsr;

        } catch (IOException ex) {
            log.error("shouldn't happen", ex);
            return null;
        }
    }


    @Override
    public ActionResponse getActionResponse() {
        return obfuscateIndicesStatsResponse(isr);
    }


}
