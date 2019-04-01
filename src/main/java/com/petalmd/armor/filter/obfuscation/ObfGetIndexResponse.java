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

import com.carrotsearch.hppc.cursors.ObjectObjectCursor;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.tokeneval.MalformedConfigurationException;
import com.petalmd.armor.tokeneval.RulesEntities;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.util.ArmorConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.admin.indices.get.GetIndexResponse;
import org.elasticsearch.cluster.metadata.AliasMetaData;
import org.elasticsearch.cluster.metadata.MappingMetaData;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;

import java.io.IOException;
import java.util.*;

/**
 * @author jehuty0shift
 * Created on 18/07/17.
 */


// This class obfuscate the response obtained by GetIndexRequest.
// It does not inheritates from GetIndexResponse because its constructor is private. Thus it uses the StreamInput writeTo and readFrom abilities.

public class ObfGetIndexResponse extends ActionResponse implements ObfResponse {

    protected static final Logger log = LogManager.getLogger(ObfGetIndexResponse.class);
    final private String[] indices;
    final private ImmutableOpenMap<String, ImmutableOpenMap<String, MappingMetaData>> mappings;
    final private ImmutableOpenMap<String, List<AliasMetaData>> aliases;
    final private ImmutableOpenMap<String, Settings> settings;
    final private ImmutableOpenMap<String, Settings> defaultSettings;
    final private GetIndexResponse response;

    static private final String ITEMS_TO_OBFUSCATE = "armor.obfuscation.filter.getindexresponse.remove";

    public ObfGetIndexResponse(final GetIndexResponse response, final Settings armorSettings, final ThreadContext threadContext) {
        this.response = response;

        User user = threadContext.getTransient(ArmorConstants.ARMOR_AUTHENTICATED_USER);
        TokenEvaluator evaluator = threadContext.getTransient(ArmorConstants.ARMOR_TOKEN_EVALUATOR);

        RulesEntities entities = null;
        if(evaluator != null) {
            try {
                entities = evaluator.findEntitiesforUser(user);
            } catch (MalformedConfigurationException ex) {
                throw new ElasticsearchException("Problem in cluster configuration, contact your administrator");
            }
        }

        List<String> itemsToObfuscate = armorSettings.getAsList(ITEMS_TO_OBFUSCATE, Collections.emptyList());

        List<String> indicesToObfuscate = new ArrayList<>();
        List<String> aliasesToObfuscate = new ArrayList<>();
        List<String> mappingsToObfuscate = new ArrayList<>();
        List<String> settingsToObfuscate = new ArrayList<>();

        boolean obfuscateAllIndices = false;
        boolean obfuscateAllMappings = false;
        boolean obfuscateAllAliases = false;
        boolean obfuscateAllSettings = false;

        for (String item : itemsToObfuscate) {
            if (item.startsWith("indices")) {
                if (item.contains(".")) {
                    String indice = item.split("\\.", 2)[1];
                    indicesToObfuscate.add(indice);
                } else {
                    obfuscateAllIndices = true;
                }
            }
            if (item.startsWith("aliases")) {
                if (item.contains(".")) {
                    String alias = item.split("\\.", 2)[1];
                    aliasesToObfuscate.add(alias);
                } else {
                    obfuscateAllAliases = true;
                }
            }
            if (item.startsWith("mappings")) {
                if (item.contains(".")) {
                    String mapping = item.split("\\.", 2)[1];
                    mappingsToObfuscate.add(mapping);
                } else {
                    obfuscateAllMappings = true;
                }
            }

            if (item.startsWith("settings")) {
                if (item.contains(".")) {
                    String settings = item.split("\\.", 2)[1];
                    settingsToObfuscate.add(settings);
                } else {
                    obfuscateAllSettings = true;
                }
            }
        }

        //Indices can be obfuscated
        List<String> indicesObfuscated = new ArrayList<>();
        if (!obfuscateAllIndices) {
            for (String indice : response.getIndices()) {
                if (!indicesToObfuscate.contains(indice)) {
                    indicesObfuscated.add(indice);
                }
            }
            indices = indicesObfuscated.toArray(new String[indicesObfuscated.size()]);
        } else {
            indices = new String[0];
        }
        if (log.isDebugEnabled()) {
            log.debug("we got indices :" + Arrays.asList(indices).toString());
        }
        //Aliases can be obfuscated
        if (!obfuscateAllAliases) {
            ImmutableOpenMap.Builder<String, List<AliasMetaData>> aliasesObfuscated = ImmutableOpenMap.builder();
            Iterator<ObjectObjectCursor<String, List<AliasMetaData>>> aliasesIt = response.aliases().iterator();
            while (aliasesIt.hasNext()) {
                ObjectObjectCursor<String, List<AliasMetaData>> indexAliases = aliasesIt.next();
                List<AliasMetaData> aliasesListObfuscated = new ArrayList<>();
                for (AliasMetaData aliasMetaData : indexAliases.value) {
                    boolean canAdd = true;
                    for (String aliasToObf : aliasesToObfuscate) {
                        if (SecurityUtil.isWildcardMatch(aliasMetaData.alias(), aliasToObf, false)) {
                            canAdd = false;
                            break;
                        }
                    }
                    if (canAdd && entities != null) {
                        boolean canAddSub = false;
                        Set<String> entitiesAllowed = new HashSet<>();
                        entitiesAllowed.addAll(entities.getAliases());
                        entitiesAllowed.addAll(entities.getIndices());
                        for (String aliasAllowed : entitiesAllowed) {
                            if(SecurityUtil.isWildcardMatch(aliasMetaData.alias(),aliasAllowed,false)) {
                                canAddSub = true;
                                break;
                            }
                        }
                        canAdd = canAddSub;
                    }
                    if(canAdd) {
                        aliasesListObfuscated.add(aliasMetaData);
                    }
                }
                aliasesObfuscated.put(indexAliases.key, aliasesListObfuscated);
            }
            aliases = aliasesObfuscated.build();
        } else {
            aliases = ImmutableOpenMap.of();
        }


        //Mappings can be obfuscated
        if (!obfuscateAllIndices && !obfuscateAllMappings) {
            ImmutableOpenMap.Builder<String, ImmutableOpenMap<String, MappingMetaData>> mappingsObfuscated = ImmutableOpenMap.builder();
            Iterator<ObjectObjectCursor<String, ImmutableOpenMap<String, MappingMetaData>>> mappingIterator = response.getMappings().iterator();
            while (mappingIterator.hasNext()) {
                //Iterate over indices
                ObjectObjectCursor<String, ImmutableOpenMap<String, MappingMetaData>> mapping = mappingIterator.next();
                ImmutableOpenMap.Builder<String, MappingMetaData> mappingObfuscated = ImmutableOpenMap.builder();
                Iterator<ObjectObjectCursor<String, MappingMetaData>> metaDataIt = mapping.value.iterator();
                while (metaDataIt.hasNext()) {
                    //Iterate over types
                    ObjectObjectCursor<String, MappingMetaData> typeMapping = metaDataIt.next();
                    try {
                        Map<String, Object> typeMappingMap = typeMapping.value.sourceAsMap(); //this call returns plain mapping without type
                        Map<String, Object> typeMappingMapObf = new HashMap<>();
                        final String propertiesName = "properties";
                        if (typeMappingMap.containsKey(propertiesName) && typeMappingMap.get(propertiesName) instanceof Map) {
                            Map<String, Object> mappingMapProperties = (Map<String, Object>) typeMappingMap.get(propertiesName);
                            Map<String, Object> mappingMapPropObf = new HashMap<>();
                            for (Map.Entry<String, Object> mappingMapEntry : mappingMapProperties.entrySet()) {
                                if (!mappingsToObfuscate.contains(mappingMapEntry.getKey())) {
                                    mappingMapPropObf.put(mappingMapEntry.getKey(), mappingMapEntry.getValue());
                                } else if (log.isDebugEnabled()) {
                                    log.debug("obfuscating mapping " + mappingMapEntry.getKey());
                                }
                            }
                            typeMappingMapObf.put(propertiesName, mappingMapPropObf);
                        }
                        for (Map.Entry<String, Object> mappingObj : typeMappingMap.entrySet()) {
                            if (!mappingObj.getKey().equals(propertiesName)) {
                                typeMappingMapObf.put(mappingObj.getKey(), mappingObj.getValue());
                            }
                        }
                        // Construct a MappingMetadata with the type.
                        MappingMetaData metadataObf = new MappingMetaData(typeMapping.key, typeMappingMapObf);
                        mappingObfuscated.put(typeMapping.key, metadataObf);
                    } catch (IOException e) {
                        log.error("Error during obfuscation", e);
                        e.printStackTrace();
                    }
                }
                mappingsObfuscated.put(mapping.key, mappingObfuscated.build());
            }
            mappings = mappingsObfuscated.build();
        } else {
            mappings = ImmutableOpenMap.of();
        }

        //Settings can be obfuscated
        if (!obfuscateAllIndices && !obfuscateAllSettings) {
            ImmutableOpenMap.Builder<String, Settings> settingsObfuscated = ImmutableOpenMap.builder();
            Iterator<ObjectObjectCursor<String, Settings>> settingsIt = response.getSettings().iterator();
            while (settingsIt.hasNext()) {
                ObjectObjectCursor<String, Settings> indexSetting = settingsIt.next();
                Settings.Builder indexSettingBuilder = Settings.builder();
                String indexName = indexSetting.key;
                Settings indexSettingValue = indexSetting.value;
                indexSettingValue.keySet().stream().filter(e -> !settingsToObfuscate.contains(e)).forEach(e -> indexSettingBuilder.put(e, indexSettingValue.get(e)));
                settingsObfuscated.put(indexName, indexSettingBuilder.build());
            }
            settings = settingsObfuscated.build();
        } else {
            settings = ImmutableOpenMap.of();
        }
        //TO DO handle defaults settings too
        defaultSettings = ImmutableOpenMap.of();

    }

    @Override
    public ActionResponse getActionResponse() {


        BytesStreamOutput bSO = new BytesStreamOutput();
        try {
            writeTo(bSO);
            response.readFrom(bSO.bytes().streamInput());
            return response;
        } catch (IOException e) {
            log.error("Couldn't modify Response", e);
            return null;
        } finally {
            //only to enforce best practices.
            bSO.close();
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeStringArray(indices);
        out.writeVInt(mappings.size());
        for (ObjectObjectCursor<String, ImmutableOpenMap<String, MappingMetaData>> indexEntry : mappings) {
            out.writeString(indexEntry.key);
            out.writeVInt(indexEntry.value.size());
            for (ObjectObjectCursor<String, MappingMetaData> mappingEntry : indexEntry.value) {
                out.writeString(mappingEntry.key);
                mappingEntry.value.writeTo(out);
            }
        }
        out.writeVInt(aliases.size());
        for (ObjectObjectCursor<String, List<AliasMetaData>> indexEntry : aliases) {
            out.writeString(indexEntry.key);
            out.writeVInt(indexEntry.value.size());
            for (AliasMetaData aliasEntry : indexEntry.value) {
                aliasEntry.writeTo(out);
            }
        }
        out.writeVInt(settings.size());
        for (ObjectObjectCursor<String, Settings> indexEntry : settings) {
            out.writeString(indexEntry.key);
            Settings.writeSettingsToStream(indexEntry.value, out);
        }
        //No need to check for Version since this call is purely internal
        out.writeVInt(defaultSettings.size());
        for (ObjectObjectCursor<String, Settings> indexEntry : defaultSettings) {
            out.writeString(indexEntry.key);
            Settings.writeSettingsToStream(indexEntry.value, out);
        }
    }


}
