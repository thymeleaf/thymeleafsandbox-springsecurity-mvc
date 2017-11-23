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
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.EhCacheBasedAclCache;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SpringSecurityMvcApplication {


	@Bean
	public EhCacheManagerFactoryBean aclCacheManager() {
		return new EhCacheManagerFactoryBean();
	}

	@Bean
	public EhCacheFactoryBean aclEhCacheFactoryBean() {
		EhCacheFactoryBean ehCacheFactoryBean = new EhCacheFactoryBean();
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
	public JdbcMutableAclService aclService(final DataSource dataSource) {
		JdbcMutableAclService service = new JdbcMutableAclService(dataSource, lookupStrategy(dataSource), aclCache());
		return service;
	}


	@Bean
	public DefaultMethodSecurityExpressionHandler defaultMethodSecurityExpressionHandler() {
		return new DefaultMethodSecurityExpressionHandler();
	}

	@Bean
	public MethodSecurityExpressionHandler createExpressionHandler(final DataSource dataSource) {
		DefaultMethodSecurityExpressionHandler expressionHandler = defaultMethodSecurityExpressionHandler();
		expressionHandler.setPermissionEvaluator(new AclPermissionEvaluator(aclService(dataSource)));
		expressionHandler.setPermissionCacheOptimizer(new AclPermissionCacheOptimizer(aclService(dataSource)));
		return expressionHandler;
	}



	@Bean
	public ApplicationRunner runner(final JdbcTemplate jdbcTemplate) {

		return (args -> {
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
