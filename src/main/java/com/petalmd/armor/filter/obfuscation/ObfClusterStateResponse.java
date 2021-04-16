package com.petalmd.armor.filter.obfuscation;

import com.petalmd.armor.authentication.User;
import com.petalmd.armor.tokeneval.RulesEntities;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.cluster.state.ClusterStateResponse;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.block.ClusterBlocks;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.routing.RoutingTable;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Created by jehuty0shift on 09/11/17.
 */
public class ObfClusterStateResponse implements ObfResponse {

    final ThreadContext threadContext;
    final ClusterStateResponse cStateResponse;

    public ObfClusterStateResponse(final ClusterStateResponse cStateResponse, final Settings settings, final ThreadContext threadContext) {
        this.cStateResponse = cStateResponse;
        this.threadContext = threadContext;
    }

    private ClusterState obfuscateClusterState(ClusterState state) {

        long obfVersion = state.version();

        String obfStateUUID = state.stateUUID();

        final User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
        Metadata obfMetaData;
        if (user == null) {
            obfMetaData = Metadata.EMPTY_METADATA;
        } else {
            final TokenEvaluator tokenEval = threadContext.getTransient(ArmorConstants.ARMOR_TOKEN_EVALUATOR);
            if (tokenEval == null) {
                obfMetaData = Metadata.EMPTY_METADATA;
            } else {
                final RulesEntities rulesEntities = tokenEval.findEntitiesForUser(user);
                ImmutableOpenMap.Builder<String, IndexMetadata> filteredIMBuilder = ImmutableOpenMap.builder();
                Set<String> metadataIndices = new HashSet<>();
                for (Iterator<String> it = state.getMetadata().indices().keysIt(); it.hasNext(); ) {
                    String metadataIndex = it.next();
                    metadataIndices.add(metadataIndex);
                }
                Set<String> filteredIndexed = filterIndicesForUser(metadataIndices, rulesEntities);
                filteredIndexed.stream().forEach(i -> filteredIMBuilder.put(i, state.getMetadata().index(i)));
                obfMetaData = Metadata.builder()
                        .indices(filteredIMBuilder.build())
                        .build();
            }
        }

        RoutingTable obfRTable = new RoutingTable.Builder().build();

        DiscoveryNodes obfNodes = DiscoveryNodes.EMPTY_NODES;

        ClusterBlocks obfClusterBlocks = ClusterBlocks.EMPTY_CLUSTER_BLOCK;

        ImmutableOpenMap.Builder<String, ClusterState.Custom> obfCustomsBuilder = ImmutableOpenMap.builder();

        int obfMinimumMasterNodes = state.getMinimumMasterNodesOnPublishingMaster();

        return new ClusterState(state.getClusterName(), obfVersion, obfStateUUID, obfMetaData, obfRTable, obfNodes, obfClusterBlocks, obfCustomsBuilder.build(), obfMinimumMasterNodes, false);
    }


    private Set<String> filterIndicesForUser(final Set<String> indexNames, RulesEntities rulesEntities) {
        Set<String> filteredIndexed = new HashSet<>();
        for (String indexAllowed : rulesEntities.getIndices()) {
            if (indexAllowed.contains("*")) {
                filteredIndexed.addAll(indexNames.stream().filter(i -> SecurityUtil.isWildcardMatch(i, indexAllowed, false)).collect(Collectors.toList()));
            } else {
                if (indexNames.contains(indexAllowed)) {
                    filteredIndexed.add(indexAllowed);
                }
            }
        }
        for (String aliasAllowed : rulesEntities.getAliases()) {
            if (aliasAllowed.contains("*")) {
                filteredIndexed.addAll(indexNames.stream().filter(i -> SecurityUtil.isWildcardMatch(i, aliasAllowed, false)).collect(Collectors.toList()));
            } else {
                if (indexNames.contains(aliasAllowed)) {
                    filteredIndexed.add(aliasAllowed);
                }
            }
        }
        return filteredIndexed;
    }

    @Override
    public ActionResponse getActionResponse() {
        return new ClusterStateResponse(cStateResponse.getClusterName(), obfuscateClusterState(cStateResponse.getState()), cStateResponse.isWaitForTimedOut());
    }
}
