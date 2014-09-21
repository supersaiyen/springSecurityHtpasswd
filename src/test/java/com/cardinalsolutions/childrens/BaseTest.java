package com.cardinalsolutions.childrens;

import org.junit.Before;
import org.mockito.MockitoAnnotations;

public abstract class BaseTest {
	
	@Before
	public void beforeMethod() throws Exception{
		MockitoAnnotations.initMocks(this);
	}

}
