package com.petalmd.armor.tokeneval;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by bdiasse on 05/04/17.
 */
public class RulesEntities {

    private Set<String> indices;

    private Set<String> aliases;

    public RulesEntities() {
        indices = new HashSet<>();
        aliases = new HashSet<>();
    }

    public void addIndex(String index){
        indices.add(index);
    }

    public void addIndices(Collection<String> newIndices) {
        indices.addAll(newIndices);
        indices.remove("*");
    }

    public void addAliases(Collection<String> newAliases) {
        aliases.addAll(newAliases);
        aliases.remove("*");
    }

    public void addAlias(String alias) {
        aliases.add(alias);
    }

    public Set<String> getAliases() {
        return aliases;
    }

    public Set<String> getIndices() {
        return indices;
    }

}
