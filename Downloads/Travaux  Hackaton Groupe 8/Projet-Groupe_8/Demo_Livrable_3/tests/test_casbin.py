import casbin

def test_rbac():
    enforcer = casbin.Enforcer('config/model.conf', 'config/policy.csv')

    tests = [
        ("alice",   "admin_panel",  "read",   True),
        ("alice",   "users",        "delete", True),
        ("bob",     "historiques",  "write",  True),
        ("bob",     "admin_panel",  "write",  False),
        ("charlie", "predictions",  "read",   True),
        ("charlie", "historiques",  "write",  False),
        ("charlie", "admin_panel",  "read",   False),
        ("charlie", "export",       "read",   False),
        ("diana",   "audit_logs",   "read",   True),
        ("diana",   "historiques",  "write",  False),
    ]

    print("\n" + "="*65)
    print(f"{'Utilisateur':<12} {'Ressource':<16} {'Action':<10} {'Résultat':<10} {'Statut'}")
    print("="*65)

    all_pass = True
    for user, resource, action, expected in tests:
        result = enforcer.enforce(user, resource, action)
        status = "OK" if result == expected else "ECHEC"
        if result != expected:
            all_pass = False
        label = "AUTORISE" if result else "REFUSE"
        print(f"{user:<12} {resource:<16} {action:<10} {label:<10} {status}")

    print("="*65)
    if all_pass:
        print("Tous les tests passent ! Politique RBAC correcte.")
    else:
        print("Des tests ont échoué — vérifier policy.csv")

if __name__ == "__main__":
    test_rbac()
