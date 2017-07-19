/*
 * Copyright 2017 PetalMD.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.petalmd.armor.filter.obfuscation;

import org.elasticsearch.Version;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.cluster.node.info.NodeInfo;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoAction;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.bootstrap.Elasticsearch;
import org.elasticsearch.client.ElasticsearchClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.plugins.PluginInfo;

import java.io.IOException;
import java.util.Map;

/**
 * @author jehuty0shift
 * Created by jehuty0shift on 10/03/17.
 */
public class ObfNodesInfoResponse extends NodesInfoResponse implements ObfResponse{


    public ObfNodesInfoResponse(NodesInfoResponse response, Settings settings) {
        super(response.getClusterName(), response.getNodes());
    }

    private String getPrivateIP(int index) {
        //This function is not 100% correct but ok for up to 1000 nodes.
        int subNet1 = 0;
        if (index / 255 != 0) {
            subNet1 = index / 255;
        }
        int subNet2 = (index % 255) + (subNet1 / 255);
        if (subNet2 > 255){
            subNet2 = subNet2 - 255;
            subNet1++;
        }
        return "172.16." + subNet1 + "." + subNet2;
    }


    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.field("cluster_name", getClusterName().value(), XContentBuilder.FieldCaseConversion.NONE);

        builder.startObject("nodes");
        int index = 0; //starts at 1 for getPrivateIP.
        for (NodeInfo nodeInfo : this) {
            index++;
            String obfPrivateIP = getPrivateIP(index);
            builder.startObject(nodeInfo.getNode().id(), XContentBuilder.FieldCaseConversion.NONE);

            builder.field("name", nodeInfo.getNode().name(), XContentBuilder.FieldCaseConversion.NONE);
            builder.field("transport_address", obfPrivateIP + ":9300", XContentBuilder.FieldCaseConversion.NONE);
            builder.field("host", obfPrivateIP, XContentBuilder.FieldCaseConversion.NONE);
            builder.field("ip", obfPrivateIP, XContentBuilder.FieldCaseConversion.NONE);

            builder.field("version", Version.CURRENT.number());
            builder.field("build", nodeInfo.getBuild().hashShort());

            if (nodeInfo.getServiceAttributes() != null) {
                for (Map.Entry<String, String> nodeAttribute : nodeInfo.getServiceAttributes().entrySet()) {
                    if (nodeAttribute.getKey() == "http_address") {
                        builder.field(nodeAttribute.getKey(), obfPrivateIP + ":9200", XContentBuilder.FieldCaseConversion.NONE);
                    }
                }
            }

            if (!nodeInfo.getNode().attributes().isEmpty()) {
                builder.startObject("attributes");
                builder.field("master", nodeInfo.getNode().attributes().get("master"));
                builder.endObject();
            }


            if (nodeInfo.getSettings() != null) {
                builder.startObject("settings");
                builder.field("bind_host", "0.0.0.0", XContentBuilder.FieldCaseConversion.NONE);
                builder.startObject("node");
                builder.field("name", nodeInfo.getNode().getName());
                builder.field("data", nodeInfo.getNode().dataNode());
                builder.field("master", nodeInfo.getNode().masterNode());
                builder.endObject();
                builder.endObject();
            }

            builder.startObject("http");
            builder.array("bound_address","[::]:9250");
            builder.field("publish_address",obfPrivateIP + ":9200");
            builder.field("max_content_length_in_bytes",104857600);
            builder.endObject();

            if (nodeInfo.getPlugins() != null) {
                builder.startArray("plugins");
                for (PluginInfo pluginInfo : nodeInfo.getPlugins().getPluginInfos()) {
                    if (pluginInfo.getName().equals("delete-by-query")) {
                        pluginInfo.toXContent(builder, params);
                    }
                }
                builder.endArray();
                builder.startArray("modules");
                for (PluginInfo moduleInfo : nodeInfo.getPlugins().getModuleInfos()) {
                    moduleInfo.toXContent(builder, params);
                }
                builder.endArray();
            }
            builder.endObject();
        }

        builder.endObject();
        return builder;
    }

    @Override
    public String toString() {
        try {
            XContentBuilder builder = XContentFactory.jsonBuilder().prettyPrint();
            builder.startObject();
            toXContent(builder, EMPTY_PARAMS);
            builder.endObject();
            return builder.string();
        } catch (IOException e) {
            return "{ \"error\" : \"" + e.getMessage() + "\"}";
        }
    }

    @Override
    public ActionResponse getActionResponse() {
        return this;
    }
}
