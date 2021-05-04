package tacos.data;

import org.springframework.data.repository.CrudRepository;

import tacos.Taco;

public interface TacoRepository2 extends CrudRepository<Taco, Long>{

//	Taco save(Taco design);
}
