/* Copyright 2011 Google Inc. All Rights Reserved.
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

package net.java.otr4j.session;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Properties;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.OtrException;
import net.java.otr4j.OtrKeyManagerImpl;
import net.java.otr4j.OtrKeyManagerStore;
import net.java.otr4j.crypto.SM;
import net.java.otr4j.crypto.SM.SMException;
import net.java.otr4j.session.OtrSm;
import net.java.otr4j.session.OtrSm.OtrSmEngineHost;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.TLV;

import org.easymock.EasyMockSupport;
import org.jivesoftware.smack.util.Base64;
import org.junit.Before;
import org.junit.Test;

public class OtrSmTest extends EasyMockSupport {
    class MemoryPropertiesStore implements OtrKeyManagerStore {
        private Properties properties = new Properties();

        public MemoryPropertiesStore() {
        }

        public void setProperty(String id, boolean value) {
            properties.setProperty(id, "true");
        }

        public void setProperty(String id, byte[] value) {
            properties.setProperty(id, new String(Base64.encodeBytes(value)));
        }

        public void removeProperty(String id) {
            properties.remove(id);

        }

        public byte[] getPropertyBytes(String id) {
            String value = properties.getProperty(id);

            if (value != null)
                return Base64.decode(value);
            return 
                    null;
        }

        public boolean getPropertyBoolean(String id, boolean defaultValue) {
            try {
                return Boolean.valueOf(properties.get(id).toString());
            } catch (Exception e) {
                return defaultValue;
            }
        }
    }

    OtrSm sm_a;
    OtrSm sm_b;
    private OtrKeyManagerImpl manager_a;
    private OtrKeyManagerImpl manager_b;
    private SessionID session_a;
    private SessionID session_b;
    private OtrSmEngineHost host_a;
    private OtrSmEngineHost host_b;

    @Before
    public void setUp() throws Exception {
        manager_a = new OtrKeyManagerImpl(new MemoryPropertiesStore());
        manager_b = new OtrKeyManagerImpl(new MemoryPropertiesStore());
        AuthContextImpl ca = new AuthContextImpl(createNiceMock(Session.class));
        AuthContextImpl cb = new AuthContextImpl(createNiceMock(Session.class));
        ca.setRemoteDHPublicKey((DHPublicKey)cb.getLocalDHKeyPair().getPublic());
        cb.setRemoteDHPublicKey((DHPublicKey)ca.getLocalDHKeyPair().getPublic());
        session_a = new SessionID("a1", "ua", "xmpp");
        session_b = new SessionID("a1", "ub", "xmpp");
        manager_a.generateLocalKeyPair(session_a);
        manager_b.generateLocalKeyPair(session_b);
        manager_a.savePublicKey(session_a, manager_b.loadLocalKeyPair(session_b).getPublic());
        manager_b.savePublicKey(session_b, manager_a.loadLocalKeyPair(session_a).getPublic());
        host_a = createNiceMock(OtrSmEngineHost.class);
        host_b = createNiceMock(OtrSmEngineHost.class);
        sm_a = new OtrSm(ca, manager_a, session_a, host_a);
        sm_b = new OtrSm(cb, manager_b, session_b, host_b);
    }

    @Test
    public void testSuccess() throws Exception {
        replayAll();
        List<TLV> tlvs = sm_a.initRespondSmp(null, "xyz", true);
        assertEquals(SM.EXPECT2, sm_a.smstate.nextExpected);
        assertEquals(1, tlvs.size());

        runMiddleOfProtocol(tlvs);
        assertTrue(manager_b.isVerified(session_b));

        assertTrue(manager_a.isVerified(session_a));
    }

    @Test
    public void testSuccess_question() throws Exception {
        replayAll();
        List<TLV> tlvs = sm_a.initRespondSmp("qqq", "xyz", true);
        assertEquals(SM.EXPECT2, sm_a.smstate.nextExpected);
        assertEquals(1, tlvs.size());

        runMiddleOfProtocol(tlvs);

        assertTrue(manager_b.isVerified(session_b));

        assertTrue(manager_a.isVerified(session_a));
    }

    @Test
    public void testFailure() throws Exception {
        replayAll();
        List<TLV> tlvs = sm_a.initRespondSmp(null, "abc", true);
        assertEquals(SM.EXPECT2, sm_a.smstate.nextExpected);
        assertEquals(1, tlvs.size());

        runMiddleOfProtocol(tlvs);

        assertFalse(manager_b.isVerified(session_b));

        assertFalse(manager_a.isVerified(session_a));
    }

    @Test
    public void testFailure_question() throws Exception {
        replayAll();
        List<TLV> tlvs = sm_a.initRespondSmp("qqq", "abc", true);
        assertEquals(SM.EXPECT2, sm_a.smstate.nextExpected);
        assertEquals(1, tlvs.size());

        runMiddleOfProtocol(tlvs);

        assertFalse(manager_b.isVerified(session_b));

        assertFalse(manager_a.isVerified(session_a));
    }

    private void runMiddleOfProtocol(List<TLV> tlvs) throws SMException, OtrException {
        tlvs = sm_b.doProcessTlv(tlvs.get(0));
        assertEquals(SM.EXPECT1, sm_b.smstate.nextExpected);
        assertNull(tlvs);

        tlvs = sm_b.initRespondSmp(null, "xyz", false);
        assertEquals(SM.EXPECT3, sm_b.smstate.nextExpected);
        assertEquals(1, tlvs.size());

        tlvs = sm_a.doProcessTlv(tlvs.get(0));
        assertEquals(SM.EXPECT4, sm_a.smstate.nextExpected);
        assertEquals(1, tlvs.size());

        assertFalse(manager_a.isVerified(session_a));
        assertFalse(manager_b.isVerified(session_b));

        tlvs = sm_b.doProcessTlv(tlvs.get(0));
        assertEquals(SM.EXPECT1, sm_b.smstate.nextExpected);
        assertEquals(1, tlvs.size());

        tlvs = sm_a.doProcessTlv(tlvs.get(0));
        assertEquals(SM.EXPECT1, sm_a.smstate.nextExpected);

        assertNull(tlvs);
    }
}
