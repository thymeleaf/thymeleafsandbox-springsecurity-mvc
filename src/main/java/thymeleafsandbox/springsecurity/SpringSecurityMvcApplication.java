package thymeleafsandbox.springsecurity;

import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.ehcache.EhCacheFactoryBean;
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.acls.AclPermissionCacheOptimizer;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.EhCacheBasedAclCache;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SpringSecurityMvcApplication {


	@Bean
	public EhCacheManagerFactoryBean aclCacheManager() {
		return new EhCacheManagerFactoryBean();
	}

	@Bean
	public EhCacheFactoryBean aclEhCacheFactoryBean() {
		final EhCacheFactoryBean ehCacheFactoryBean = new EhCacheFactoryBean();
		ehCacheFactoryBean.setCacheManager(aclCacheManager().getObject());
		ehCacheFactoryBean.setCacheName("aclCache");
		return ehCacheFactoryBean;
	}

	@Bean
	public DefaultPermissionGrantingStrategy permissionGrantingStrategy() {
		ConsoleAuditLogger consoleAuditLogger = new ConsoleAuditLogger();
		return new DefaultPermissionGrantingStrategy(consoleAuditLogger);
	}

	@Bean
	public AclAuthorizationStrategy aclAuthorizationStrategy() {
		return new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_ADMINISTRATOR"));
	}

	@Bean
	public AclCache aclCache() {
		return new EhCacheBasedAclCache(
				aclEhCacheFactoryBean().getObject(),
				permissionGrantingStrategy(),
				aclAuthorizationStrategy());
	}

	@Bean
	public LookupStrategy lookupStrategy(final DataSource dataSource) {
		return new BasicLookupStrategy(dataSource, aclCache(), aclAuthorizationStrategy(), new ConsoleAuditLogger());
	}

	@Bean
	public MutableAclService aclService(final DataSource dataSource) {
		return new JdbcMutableAclService(dataSource, lookupStrategy(dataSource), aclCache());
	}


	@Bean
	public DefaultMethodSecurityExpressionHandler defaultMethodSecurityExpressionHandler() {
		return new DefaultMethodSecurityExpressionHandler();
	}

	@Bean
	public MethodSecurityExpressionHandler createExpressionHandler(final DataSource dataSource) {
		final DefaultMethodSecurityExpressionHandler expressionHandler = defaultMethodSecurityExpressionHandler();
		expressionHandler.setPermissionEvaluator(new AclPermissionEvaluator(aclService(dataSource)));
		expressionHandler.setPermissionCacheOptimizer(new AclPermissionCacheOptimizer(aclService(dataSource)));
		return expressionHandler;
	}



	@Bean
	public ApplicationRunner runner(final MutableAclService aclService, final JdbcTemplate jdbcTemplate) {

		return (args -> {

			SecurityContextHolder.getContext().setAuthentication(
					new UsernamePasswordAuthenticationToken("jim", "demo"));

			final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			System.out.println(authentication);

			ObjectIdentity oi = new ObjectIdentityImpl("page", Long.valueOf(1));
			Sid sid = new PrincipalSid("jim");
			Permission p = BasePermission.ADMINISTRATION;

			// Create or update the relevant ACL
			MutableAcl acl = null;
			try {
				acl = (MutableAcl) aclService.readAclById(oi);
			} catch (NotFoundException nfe) {
				acl = aclService.createAcl(oi);
			}

			// Now grant some permissions via an access control entry (ACE)
			acl.insertAce(acl.getEntries().size(), p, sid, true);
			aclService.updateAcl(acl);


			final List<Map<String,Object>> result =
					jdbcTemplate.queryForList(
							"SELECT table_schema,table_name " +
							"FROM INFORMATION_SCHEMA.TABLES " +
							"where table_schema <> 'INFORMATION_SCHEMA' AND table_schema <> 'SYSTEM_LOBS'");

			System.out.println(result);

		});

	}



	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityMvcApplication.class, args);
	}
}
