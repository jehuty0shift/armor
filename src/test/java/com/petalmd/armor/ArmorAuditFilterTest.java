package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.audit.KafkaAuditFactory;
import com.petalmd.armor.common.KafkaOutputConsumer;
import com.petalmd.armor.util.ConfigConstants;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.CreateIndexRequest;
import org.elasticsearch.client.indices.CreateIndexResponse;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class ArmorAuditFilterTest extends AbstractArmorTest {

    @Test
    public void testAuditOnCreation() throws Exception {

        username = "logs-xv-12345";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final AtomicReference<String> indexName = new AtomicReference<>(username + "-i-test-1");
        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "lifecycle_index", "forbidden")
                .putList("armor.actionrequestfilter.lifecycle_index.allowed_actions", "indices:admin/create")
                .putList("armor.actionrequestfilter.forbidden.allowed_actions", "indices:data/read/scroll", "indices:data/read/scroll/clear")
                .put(ConfigConstants.ARMOR_AUDIT_KAFKA_ENABLED, true)
                .put(ConfigConstants.ARMOR_AUDIT_KAFKA_CLIENT_ID, "test-audit-filter")
                .put(ConfigConstants.ARMOR_AUDIT_KAFKA_USE_IMPL, false)
                .put(authSettings).build();

        KafkaOutputConsumer mockOutput = new KafkaOutputConsumer(ldpGelf -> {});
        KafkaAuditFactory kFactory = KafkaAuditFactory.makeInstance(settings);
        kFactory.setKafkaOutput(mockOutput);

        startES(settings);
        setupTestData("ac_rules_25.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        final AtomicReference<Boolean> hasSent = new AtomicReference<>();
        hasSent.set(false);


        mockOutput.setConsumer(ldpGelf -> {
            Map<String, Object> fields = ldpGelf.getDocumentMap();
            Assert.assertEquals("indices:admin/create", fields.get("_action"));
            Assert.assertEquals(username, fields.get("_user"));
            Assert.assertTrue(fields.get("_items").toString().contains(indexName.get()));
            hasSent.set(true);
        });


        CreateIndexResponse cIResp = client.indices().create(
                new CreateIndexRequest(indexName.get())
                        .settings(Settings.builder()
                                .put("index.number_of_shards", 3)
                                .put("index.number_of_replicas", 1)
                                .build())
                , RequestOptions.DEFAULT);


        Assert.assertTrue(hasSent.get());
        Assert.assertTrue(cIResp.isAcknowledged());
    }

}