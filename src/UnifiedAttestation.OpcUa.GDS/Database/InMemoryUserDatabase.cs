using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Server;
using Opc.Ua.Server.UserDatabase;

namespace UnifiedAttestation.OpcUa.GDS.Database;

public class InMemoryUsersDatabase : IUserDatabase
{
    #region IUserDatabase

    public void Initialize()
    {
        lock (m_lock)
        {
            m_users.Clear();
        }
    }

    public bool CreateUser(string userName, string password, IEnumerable<Role> roles)
    {
        if (string.IsNullOrEmpty(userName))
        {
            throw new ArgumentException("UserName cannot be empty.", nameof(userName));
        }
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password cannot be empty.", nameof(password));
        }

        lock (m_lock)
        {
            //Check if the user already exists
            if (m_users.ContainsKey(userName))
            {
                return false;
            }

            string hash = PasswordHasher.Hash(password);
            var userId = Guid.NewGuid();

            var roleRecords = new List<RoleRecord>();
            foreach (var role in roles)
            {
                roleRecords.Add(RoleRecord.FromRole(role, userId));
            }

            var user = new UserRecord
            {
                ID = userId,
                UserName = userName,
                Hash = hash,
                Roles = roleRecords,
            };

            m_users[userName] = user;
            return true;
        }
    }

    public bool DeleteUser(string userName)
    {
        if (string.IsNullOrEmpty(userName))
        {
            throw new ArgumentException("UserName cannot be empty.", nameof(userName));
        }

        lock (m_lock)
        {
            if (!m_users.ContainsKey(userName))
            {
                return false;
            }

            m_users.Remove(userName);
            return true;
        }
    }

    public bool CheckCredentials(string userName, string password)
    {
        if (string.IsNullOrEmpty(userName))
        {
            throw new ArgumentException("UserName cannot be empty.", nameof(userName));
        }
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password cannot be empty.", nameof(password));
        }

        lock (m_lock)
        {
            if (!m_users.TryGetValue(userName, out UserRecord? user) || user == null)
            {
                return false;
            }

            return PasswordHasher.Check(user.Hash, password);
        }
    }

    public IEnumerable<Role> GetUserRoles(string userName)
    {
        if (string.IsNullOrEmpty(userName))
        {
            throw new ArgumentException("UserName cannot be empty.", nameof(userName));
        }

        lock (m_lock)
        {
            if (!m_users.TryGetValue(userName, out UserRecord? user) || user == null)
            {
                throw new ArgumentException("No user found with the UserName " + userName);
            }

            var roles = new List<Role>();
            foreach (var role in user.Roles)
            {
                roles.Add(role.ToRole());
            }

            return roles;
        }
    }

    public bool ChangePassword(string userName, string oldPassword, string newPassword)
    {
        if (string.IsNullOrEmpty(userName))
        {
            throw new ArgumentException("UserName cannot be empty.", nameof(userName));
        }
        if (string.IsNullOrEmpty(oldPassword))
        {
            throw new ArgumentException("Current Password cannot be empty.", nameof(oldPassword));
        }
        if (string.IsNullOrEmpty(newPassword))
        {
            throw new ArgumentException("New Password cannot be empty.", nameof(newPassword));
        }

        lock (m_lock)
        {
            if (!m_users.TryGetValue(userName, out UserRecord? user) || user == null)
            {
                return false;
            }

            if (PasswordHasher.Check(user.Hash, oldPassword))
            {
                var newHash = PasswordHasher.Hash(newPassword);
                user.Hash = newHash;
                return true;
            }
            return false;
        }
    }

    #endregion

    #region Additional Helper Methods

    /// <summary>
    /// Getting all users in the database.
    /// </summary>
    /// <returns>Collection of usernames</returns>
    public IEnumerable<string> GetAllUsers()
    {
        lock (m_lock)
        {
            return m_users.Keys.ToList();
        }
    }

    /// <summary>
    /// Checks if a user exists in the database.
    /// </summary>
    /// <param name="userName">The username to check</param>
    /// <returns>´true´ if user exists, ´false´ otherwise</returns>
    public bool UserExists(string userName)
    {
        if (string.IsNullOrEmpty(userName))
        {
            return false;
        }

        lock (m_lock)
        {
            return m_users.ContainsKey(userName);
        }
    }

    /// <summary>
    /// Updates user roles with new set of roles, adding them.
    /// </summary>
    /// <param name="userName">The username</param>
    /// <param name="roles">New roles to assign</param>
    /// <returns>´true´ if successful, ´false´ if user not found</returns>
    public bool UpdateUserRoles(string userName, IEnumerable<Role> roles)
    {
        if (string.IsNullOrEmpty(userName))
        {
            throw new ArgumentException("UserName cannot be empty.", nameof(userName));
        }

        lock (m_lock)
        {
            if (!m_users.TryGetValue(userName, out UserRecord? user) || user == null)
            {
                return false;
            }

            user.Roles.Clear();
            foreach (var role in roles)
            {
                user.Roles.Add(RoleRecord.FromRole(role, user.ID));
            }

            return true;
        }
    }

    /// <summary>
    /// Gets the total number of users in the database.
    /// </summary>
    /// <returns>User count</returns>
    public int GetUserCount()
    {
        lock (m_lock)
        {
            return m_users.Count;
        }
    }

    public bool CreateUser(string userName, ReadOnlySpan<byte> password, ICollection<Role> roles)
    {
        if (string.IsNullOrEmpty(userName))
        {
            throw new ArgumentException("UserName cannot be empty.", nameof(userName));
        }
        if (password.Length == 0)
        {
            throw new ArgumentException("Password cannot be empty.", nameof(password));
        }

        lock (m_lock)
        {
            //Check if the user already exists
            if (m_users.ContainsKey(userName))
            {
                return false;
            }

            string hash = PasswordHasher.Hash(password);
            var userId = Guid.NewGuid();

            var roleRecords = new List<RoleRecord>();
            foreach (var role in roles)
            {
                roleRecords.Add(RoleRecord.FromRole(role, userId));
            }

            var user = new UserRecord
            {
                ID = userId,
                UserName = userName,
                Hash = hash,
                Roles = roleRecords,
            };

            m_users[userName] = user;
            return true;
        }
    }

    public bool CheckCredentials(string userName, ReadOnlySpan<byte> password) => throw new NotImplementedException();

    ICollection<Role> IUserDatabase.GetUserRoles(string userName) => throw new NotImplementedException();

    public bool ChangePassword(string userName, ReadOnlySpan<byte> oldPassword, ReadOnlySpan<byte> newPassword) =>
        throw new NotImplementedException();

    #endregion

    #region Private Fields

    //Ensure mutual exclusion.
    private readonly object m_lock = new object();
    private readonly Dictionary<string, UserRecord> m_users = new Dictionary<string, UserRecord>(
        StringComparer.OrdinalIgnoreCase
    );
    private ILogger<InMemoryUsersDatabase>? m_logger;

    #endregion

    #region Constructors
    public InMemoryUsersDatabase()
        : this(null) { }

    public InMemoryUsersDatabase(ILogger<InMemoryUsersDatabase>? logger = null)
    {
        m_logger = logger;
    }
    #endregion

    #region Data Structures (since using in memory database)
    //Based on database schema defined in usersdb.edmx.sql
    internal class UserRecord
    {
        public Guid ID { get; set; }
        public required string UserName { get; set; }
        public required string Hash { get; set; }
        public List<RoleRecord> Roles { get; set; } = new List<RoleRecord>();
    }

    internal class RoleRecord
    {
        public Guid Id { get; set; }
        public int? RoleId { get; set; }
        public required string Name { get; set; }
        public Guid UserID { get; set; }
        public int NamespaceIndex { get; set; }

        public Role ToRole()
        {
            if (RoleId != null)
            {
                return new Role(new NodeId((uint)RoleId, (ushort)NamespaceIndex), Name);
            }
            return new Role(NodeId.Null, Name);
        }

        public static RoleRecord FromRole(Role role, Guid userId)
        {
            return new RoleRecord
            {
                Id = Guid.NewGuid(),
                Name = role.Name,
                RoleId = (int?)(role.RoleId.Identifier as uint?),
                NamespaceIndex = role.RoleId.NamespaceIndex,
                UserID = userId,
            };
        }
    }

    #endregion
}

public static class PasswordHasher
{
    #region Internal Fields / Constants

    private const int kSaltSize = 16; // 128 bit
    private const int kIterations = 10000; // 10k
    private const int kKeySize = 32; // 256 bit
    #endregion

    #region IPasswordHasher

    public static bool Check(string hash, string password)
    {
        char[] separator = ['.'];
        string[] parts = hash.Split(separator, 3);

        if (parts.Length != 3)
        {
            throw new FormatException(
                "Unexpected hash format. " + "Should be formatted as `{iterations}.{salt}.{hash}`"
            );
        }

        int iterations = Convert.ToInt32(parts[0], CultureInfo.InvariantCulture.NumberFormat);
        byte[] salt = Convert.FromBase64String(parts[1]);
        byte[] key = Convert.FromBase64String(parts[2]);

#if NETSTANDARD2_0 || NET462
#pragma warning disable CA5379 // Ensure Key Derivation Function algorithm is sufficiently strong
        using (var algorithm = new Rfc2898DeriveBytes(password, salt, iterations))
#pragma warning restore CA5379 // Ensure Key Derivation Function algorithm is sufficiently strong
#else

#endif
        {
            byte[] keyToCheck = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                iterations,
                HashAlgorithmName.SHA512,
                kKeySize
            );
            bool verified = keyToCheck.SequenceEqual(key);

            return verified;
        }
    }

    public static string Hash(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(kSaltSize);

        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, kIterations, HashAlgorithmName.SHA512, kKeySize);

        string saltBase64 = Convert.ToBase64String(salt);
        string keyBase64 = Convert.ToBase64String(key);

        return $"{kIterations}.{saltBase64}.{keyBase64}";
    }

    #endregion
}
