package com.petalmd.armor;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.petalmd.armor.util.ConfigConstants;
import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.query.TermQueryBuilder;
import org.elasticsearch.index.reindex.BulkByScrollResponse;
import org.elasticsearch.index.reindex.UpdateByQueryAction;
import org.elasticsearch.index.reindex.UpdateByQueryRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.script.Script;
import org.elasticsearch.script.ScriptType;
import org.junit.Assert;
import org.junit.Test;

import java.util.Collections;

/**
 * Created by jehuty0shift on 21/11/18.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class UpdateByQueryTest extends AbstractArmorTest {

    @Test
    public void testUpdateByQuery() throws Exception {
        username = "jacksonm";
        password = "secret";
        Settings authSettings = getAuthSettings(false, "ceo");

        final String index = "dev";

        final Settings settings = Settings.builder().putList("armor.actionrequestfilter.names", "updatebyquery", "forbidden")
                .putList("armor.actionrequestfilter.updatebyquery.allowed_actions", UpdateByQueryAction.NAME)
                .putList("armor.actionrequestfilter.forbidden.forbidden_actions", "cluster:admin*")
                .put(ConfigConstants.ARMOR_KIBANA_HELPER_ENABLED, true)
                .put(authSettings)
                .build();

        startES(settings);

        setupTestDataWithFilteredAlias("ac_rules_17.json");

        RestHighLevelClient client = getRestClient(false, username, password);

        UpdateByQueryRequest ubq = new UpdateByQueryRequest(index)
                .setQuery(new TermQueryBuilder("user", "ronaldihno"))
                .setScript(new Script(ScriptType.INLINE, "painless",
                        "ctx._source.message = 'message changed'",
                        Collections.emptyMap()));


        BulkByScrollResponse ubqResp = client.updateByQuery(ubq, RequestOptions.DEFAULT);

        Assert.assertTrue(ubqResp.getUpdated() > 0);
        Assert.assertTrue(ubqResp.getBulkFailures().isEmpty());


        Assert.assertTrue(ubqResp.getUpdated() == ubqResp.getTotal());

        log.info("result is {}", ubqResp.toString());


        UpdateByQueryRequest ubq2 = new UpdateByQueryRequest("financial")
                .setQuery(new TermQueryBuilder("user", "zeus"))
                .setScript(new Script(ScriptType.INLINE, "painless",
                        "ctx._source.message = 'message changed'",
                        Collections.emptyMap()));

        ElasticsearchStatusException error = expectThrows(ElasticsearchStatusException.class, () -> client.updateByQuery(ubq2, RequestOptions.DEFAULT));

        Assert.assertTrue(error.getDetailedMessage().contains("forbidden_exception"));
        Assert.assertTrue(error.getDetailedMessage().contains("DEFAULT"));
        Assert.assertTrue(error.status().equals(RestStatus.FORBIDDEN));

    }

}
