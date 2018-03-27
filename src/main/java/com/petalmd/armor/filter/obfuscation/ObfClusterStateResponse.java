package com.petalmd.armor.filter.obfuscation;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.cluster.state.ClusterStateResponse;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.block.ClusterBlocks;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.routing.RoutingTable;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.settings.Settings;

/**
 * Created by jehuty0shift on 09/11/17.
 */
public class ObfClusterStateResponse extends ClusterStateResponse implements ObfResponse {


    public ObfClusterStateResponse(final ClusterStateResponse cStateResponse, final Settings settings) {

            super(cStateResponse.getClusterName(), obfuscateClusterState(cStateResponse.getState()));
    }


    private static ClusterState obfuscateClusterState(ClusterState state) {

        long obfVersion = state.version();

        String obfStateUUID = state.stateUUID();

        MetaData obfMetaData = MetaData.EMPTY_META_DATA;

        RoutingTable obfRTable = new RoutingTable.Builder().build();

        DiscoveryNodes obfNodes = DiscoveryNodes.EMPTY_NODES;

        ClusterBlocks obfClusterBlocks = ClusterBlocks.EMPTY_CLUSTER_BLOCK;

        ImmutableOpenMap.Builder<String, ClusterState.Custom> obfCustomsBuilder = ImmutableOpenMap.builder();

        return new ClusterState(state.getClusterName(),obfVersion,obfStateUUID,obfMetaData,obfRTable,obfNodes,obfClusterBlocks,obfCustomsBuilder.build(),false);
    }


    @Override
    public ActionResponse getActionResponse() {
        return this;
    }
}
