package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.audit.KafkaAuditFactory;
import com.petalmd.armor.common.KafkaOutputConsumer;
import com.petalmd.armor.util.ConfigConstants;
import io.searchbox.client.JestResult;
import io.searchbox.indices.CreateIndex;
import kong.unirest.Unirest;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;
import org.powermock.core.classloader.annotations.PrepareForTest;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@PrepareForTest({Unirest.class})
public class ArmorAuditFilterTest extends AbstractUnitTest {

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


        HeaderAwareJestHttpClient client = getJestClient(getServerUri(false), username, password);


        CreateIndex createIndex = new CreateIndex.Builder(indexName.get()).settings(Map.of("index.number_of_shards", 3, "index.number_of_replicas", 1)).build();

        final AtomicReference<Boolean> hasSent = new AtomicReference<>();
        hasSent.set(false);


        mockOutput.setConsumer(ldpGelf -> {
            Map<String, Object> fields = ldpGelf.getDocumentMap();
            Assert.assertEquals("indices:admin/create", fields.get("_action"));
            Assert.assertEquals(username, fields.get("_user"));
            Assert.assertTrue(fields.get("_items").toString().contains(indexName.get()));
            hasSent.set(true);
        });


        Tuple<JestResult, HttpResponse> result = client.executeE(createIndex);

        Assert.assertTrue(hasSent.get());

        Assert.assertTrue(result.v1().isSucceeded());
        Assert.assertTrue(result.v1().getJsonString().contains("acknowledged"));
        Assert.assertTrue(result.v1().getJsonString().contains("true"));


    }


}
