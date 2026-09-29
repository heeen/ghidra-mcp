package com.xebyte.offline;

import com.xebyte.core.VersionControlService;
import ghidra.framework.remote.User;
import junit.framework.TestCase;

/**
 * Offline tests for {@link VersionControlService}'s pure helpers.
 *
 * <p>{@code User} is a plain Serializable value class
 * ({@code User(String, int)}, {@code getName()}, {@code getPermissionType()})
 * with no Ghidra-init transitive chain, so it is safe to instantiate in the
 * Maven offline suite.
 */
public class VersionControlServiceTest extends TestCase {

    public void testMergeUserPermission_replacesExistingEntryAndPreservesOthers() {
        User[] existing = {
            new User("alice", User.ADMIN),
            new User("bob",   User.READ_ONLY),
            new User("carol", User.WRITE),
        };
        User[] merged = VersionControlService.mergeUserPermission(existing, "bob", User.WRITE);

        assertEquals("ACL size must not shrink", 3, merged.length);
        assertEquals("alice", merged[0].getName());
        assertEquals(User.ADMIN, merged[0].getPermissionType());
        assertEquals("bob", merged[1].getName());
        assertEquals("bob's level updated", User.WRITE, merged[1].getPermissionType());
        assertEquals("carol", merged[2].getName());
        assertEquals(User.WRITE, merged[2].getPermissionType());
        // Input not mutated
        assertEquals(User.READ_ONLY, existing[1].getPermissionType());
    }

    public void testMergeUserPermission_appendsNewUser() {
        User[] existing = {
            new User("alice", User.ADMIN),
        };
        User[] merged = VersionControlService.mergeUserPermission(existing, "dave", User.READ_ONLY);

        assertEquals(2, merged.length);
        assertEquals("alice", merged[0].getName());
        assertEquals(User.ADMIN, merged[0].getPermissionType());
        assertEquals("dave", merged[1].getName());
        assertEquals(User.READ_ONLY, merged[1].getPermissionType());
    }

    public void testMergeUserPermission_handlesNullOrEmptyExisting() {
        User[] fromNull = VersionControlService.mergeUserPermission(null, "alice", User.ADMIN);
        assertEquals(1, fromNull.length);
        assertEquals("alice", fromNull[0].getName());

        User[] fromEmpty = VersionControlService.mergeUserPermission(new User[0], "alice", User.ADMIN);
        assertEquals(1, fromEmpty.length);
        assertEquals("alice", fromEmpty[0].getName());
    }

    public void testAccessLevelsParseByNameOrNumber() {
        assertEquals(Integer.valueOf(User.READ_ONLY), VersionControlService.parseAccessLevel("read_only"));
        assertEquals(Integer.valueOf(User.READ_ONLY), VersionControlService.parseAccessLevel("0"));
        assertEquals(Integer.valueOf(User.WRITE), VersionControlService.parseAccessLevel(" Write "));
        assertEquals(Integer.valueOf(User.WRITE), VersionControlService.parseAccessLevel("1"));
        assertEquals(Integer.valueOf(User.ADMIN), VersionControlService.parseAccessLevel("ADMIN"));
        assertEquals(Integer.valueOf(User.ADMIN), VersionControlService.parseAccessLevel("2"));
    }

    /** 3 was documented as admin and never existed; a missing level must not become a grant. */
    public void testAnythingElseIsNotAnAccessLevel() {
        assertNull(VersionControlService.parseAccessLevel("3"));
        assertNull(VersionControlService.parseAccessLevel(""));
        assertNull(VersionControlService.parseAccessLevel(null));
        assertNull(VersionControlService.parseAccessLevel("root"));
    }
}
