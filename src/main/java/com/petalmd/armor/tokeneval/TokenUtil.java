package com.petalmd.armor.tokeneval;

import com.petalmd.armor.util.SecurityUtil;

import java.util.Iterator;
import java.util.Set;

/**
 * Created by jehuty0shift on 09/01/2020.
 */
public class TokenUtil {

    public static boolean isNullEmptyStar(final Set<String> set) {
        return set == null || set.isEmpty() || set.contains("*");

    }

    public static boolean isStar(final Set<String> set) {
        return set != null && set.contains("*");
    }


    public static boolean containsWildcardPattern(final Set<String> set, final String pattern) {
        for (final Iterator iterator = set.iterator(); iterator.hasNext(); ) {
            final String string = (String) iterator.next();
            if (SecurityUtil.isWildcardMatch(string, pattern, false)) {
                return true;
            }
        }
        return false;

    }
}
