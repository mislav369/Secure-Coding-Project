package com.opentext.appsec.demo.security;

import com.opentext.appsec.demo.model.UserProfile;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Set;

public class WhitelistObjectInputStream extends ObjectInputStream {
    private static final Set<String> WHITELIST = Set.of(
            UserProfile.class.getName()
    );

    public WhitelistObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc)
            throws IOException, ClassNotFoundException {
        if (!WHITELIST.contains(desc.getName())) {
            throw new InvalidClassException(
                    "Blocked non whitelisted class: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
}
